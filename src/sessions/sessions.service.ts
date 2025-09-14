import {
  BadRequestException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { Request, Response } from 'express';
import { JwtPayload } from 'src/types/jwt-payload.interface';
import * as crypto from 'crypto';
import Redis from 'ioredis';
import useragent from 'useragent';

@Injectable()
export class SessionsService {
  constructor(
    @Inject('REDIS_CLIENT') private redisClient: Redis,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async sessions(req: Request) {
    const payload = req['user'] as JwtPayload;
    const userId = payload.sub;
    const currentSessionId = payload.sid; // Assuming sid is in the payload

    const sessionKeys = await this.redisClient.keys(`session:${userId}:*`);

    // Use pipeline to fetch all data at once
    const pipeline = this.redisClient.pipeline();
    sessionKeys.forEach((key) =>
      pipeline.hmget(key, 'deviceInfo', 'revoked', 'createdAt'),
    );
    const results = (await pipeline.exec()) as [[Error, string[]]] | null;

    const activeSessions: {
      sessionId: string;
      deviceInfo: string;
      createdAt: string;
      isCurrent: boolean;
    }[] = [];

    if (!results) {
      throw new Error(
        'Failed to fetch session data: Pipeline execution failed',
      );
    }

    results.forEach(([err, [deviceInfo, revoked, createdAt]], index) => {
      if (err) {
        console.error(`Error fetching session ${sessionKeys[index]}:`, err);
        return; // Skip this session on error
      }
      const sessionId = sessionKeys[index].split(':')[2];
      const isRevoked = revoked === 'true';

      if (!isRevoked) {
        const isCurrent = sessionId === currentSessionId;
        activeSessions.push({ sessionId, deviceInfo, isCurrent, createdAt });
      }
    });

    // Sort to put current session first
    activeSessions.sort((a, b) =>
      b.isCurrent === a.isCurrent ? 0 : b.isCurrent ? 1 : -1,
    );

    return {
      message: 'Get active sessions successfully',
      success: true,
      data: { sessions: activeSessions },
    };
  }

  async refresh(req: Request, res: Response) {
    const refreshToken = req.cookies.refreshToken as string;
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing, please login');
    }

    const accessToken = req.headers.authorization?.split(' ')[1];

    if (!accessToken) {
      throw new UnauthorizedException('Access token missing');
    }

    const decoded: JwtPayload = this.jwtService.decode(accessToken);
    if (!decoded || !decoded.sub || !decoded.sid) {
      throw new UnauthorizedException('Invalid token');
    }

    const userId = decoded.sub;
    const sessionId = decoded.sid;
    const sessionKey = `session:${userId}:${sessionId}`;

    const ua = useragent.parse(req.headers['user-agent']);
    const info = `${ua.os?.toString() || 'Unknown OS'} - ${ua.device?.toString() || 'Unknown Device'} - ${req.ip}`;

    const [storedRefreshToken, revoked, refreshExpiresAt, deviceInfo] =
      await this.redisClient.hmget(
        sessionKey,
        'refreshToken',
        'revoked',
        'refreshExpiresAt',
        'deviceInfo',
      );

    // Check device info match (os and device only, ignore IP for flexibility)
    const [storedOs, storedDevice, storedIp] = deviceInfo?.split(' - ') || [];
    const [currentOs, currentDevice, currentIp] = info.split(' - ');

    if (storedOs !== currentOs || storedDevice !== currentDevice) {
      const allSessionKeys = await this.redisClient.keys(`session:${userId}:*`);
      await Promise.all(
        allSessionKeys.map((key) =>
          this.redisClient.hset(key, 'revoked', 'true'),
        ),
      );

      res.clearCookie('refreshToken', {
        maxAge: 0,
        httpOnly: true,
        sameSite: 'strict',
        secure: true,
        path: '/',
      });

      throw new UnauthorizedException(
        'Device info not match, all sessions revoked',
      );
    }

    // Check Blacklist (Reuse Detection) first
    const isBlacklisted = await this.redisClient.sismember(
      'blacklist',
      refreshToken,
    );
    if (isBlacklisted) {
      const allSessionKeys = await this.redisClient.keys(`session:${userId}:*`);
      await Promise.all(
        allSessionKeys.map(
          (key) => this.redisClient.hset(key, 'revoked', 'true'), // Revoke all sessions
        ),
      );

      res.clearCookie('refreshToken', {
        maxAge: 0,
        httpOnly: true,
        sameSite: 'strict',
        secure: true,
        path: '/',
      });
      throw new UnauthorizedException('Token reused, all sessions revoked');
    }

    // Validate refreshToken match
    if (!storedRefreshToken || storedRefreshToken !== refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Check revoked and refreshExpiresAt
    if (
      revoked === 'true' ||
      (refreshExpiresAt && new Date(refreshExpiresAt) < new Date())
    ) {
      throw new UnauthorizedException(
        'Session revoked or refresh token expired',
      );
    }

    // Generate new tokens
    const newAccessToken = await this.jwtService.signAsync({
      sub: userId,
      sid: sessionId,
      roles: decoded.roles,
    });
    const newRefreshToken = crypto.randomBytes(16).toString('hex');

    // Update session
    await this.redisClient.hset(sessionKey, 'refreshToken', newRefreshToken);

    // Add old refreshToken to blacklist
    await this.redisClient.sadd('blacklist', refreshToken);
    await this.redisClient.expire('blacklist', 604800); // 7 days

    // Set new tokens
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });
    res.setHeader('Authorization', `Bearer ${newAccessToken}`);

    return {
      message: 'Tokens refreshed',
      success: true,
      data: { accessToken: newAccessToken, refreshToken: newRefreshToken },
    };
  }

  async logout(req: Request, res: Response) {
    const payload = req['user'] as JwtPayload;
    const userId = payload.sub;
    const sessionId = payload.sid;
    const sessionKey = `session:${userId}:${sessionId}`;

    // Revoke the current session
    await this.redisClient.hset(sessionKey, 'revoked', 'true');
    res.clearCookie('refreshToken', {
      maxAge: 0,
      httpOnly: true,
      sameSite: 'strict',
      secure: true,
      path: '/',
    });

    return { success: true, message: 'Logged out successfully' };
  }

  async revokeSession(sessionId: string, req: Request) {
    const payload = req['user'] as JwtPayload;
    const userId = payload.sub;

    const sessionKey = `session:${userId}:${sessionId}`;

    const exists = await this.redisClient.exists(sessionKey);
    if (exists === 0) throw new BadRequestException('Session not found');

    await this.redisClient.hset(sessionKey, 'revoked', 'true');

    return { success: true, message: 'Session revoked successfully' };
  }

  async revokeAllSessions(req: Request) {
    const payload = req['user'] as JwtPayload;
    const userId = payload.sub;
    const currentSessionId = payload.sid; // Assuming sid is in the payload

    const sessionKeys = await this.redisClient.keys(`session:${userId}:*`);

    const revokePromises = sessionKeys
      .filter((key) => {
        const sessionId = key.split(':')[2];
        return sessionId !== currentSessionId;
      })
      .map((key) => this.redisClient.hset(key, 'revoked', 'true'));

    await Promise.all(revokePromises);
    return {
      success: true,
      message: 'All sessions revoked except current',
    };
  }
}
