import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import type { Request, Response } from 'express';
import { Session } from './entities/session.entity';
import { JwtPayload } from 'src/types/jwt-payload.interface';
import { MoreThan, Repository } from 'typeorm';
import { CleanupSessionDto } from './dto/cleanup-session.dto';
import * as crypto from 'crypto';

@Injectable()
export class SessionsService {
  constructor(
    @InjectRepository(Session)
    private readonly sessionsRepository: Repository<Session>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async sessions(req: Request) {
    const payload = req['user'] as JwtPayload;

    const sessions = await this.sessionsRepository.find({
      where: {
        user: { id: payload.userId },
        revoked: false,
        expires: MoreThan(new Date()),
      },
      select: ['id', 'device', 'createdAt', 'expires'],
    });

    return {
      message: 'Get active sessions successfully',
      success: true,
      data: { sessions },
    };
  }

  async refresh(req: Request, res: Response) {
    const refreshToken = req.cookies['refreshToken'] as string;

    if (!refreshToken) throw new UnauthorizedException('No refresh token');

    const session = await this.sessionsRepository.findOne({
      where: { token: refreshToken },
      relations: ['user', 'user.roles'],
      select: {
        id: true,
        revoked: true,
        expires: true,
        token: true,
        user: {
          id: true,
          isBlocked: true,
          roles: {
            name: true,
          },
        },
      },
    });

    if (!session || session.expires < new Date() || session.revoked === true)
      throw new UnauthorizedException('Invalid refresh token');
    // Genrate new refresh every refresh token and save it
    const newRefreshToken = crypto.randomBytes(16).toString('hex');
    session.token = newRefreshToken;
    await this.sessionsRepository.save(session);

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
      maxAge: Number(
        this.configService.get('REFRESH_TOKEN_COOKIES_EXPIRATION_TIME'),
      ),
    });

    const roles = session.user.roles || [];
    const payload = {
      userId: session.user.id,
      sessionId: session.id,
      roles: roles.map((role) => role.name),
    } as JwtPayload;

    const newAccessToken = await this.jwtService.signAsync(payload, {
      expiresIn: this.configService.get(
        'ACCESS_TOKEN_EXPIRATION_TIME',
      ) as string,
    });
    res.setHeader('Authorization', `Bearer ${newAccessToken}`);

    return {
      message: 'Access token and refresh token refreshed',
      success: true,
      data: {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      },
    };
  }

  async logout(req: Request, res: Response) {
    const payload = req['user'] as JwtPayload;

    const session = await this.sessionsRepository.findOne({
      where: { id: payload.sessionId },
    });
    if (!session) throw new BadRequestException('Session not found');

    session.revoked = true;

    await this.sessionsRepository.save(session);

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
    const { userId } = req['user'] as JwtPayload;

    const session = await this.sessionsRepository.findOne({
      where: { id: sessionId },
      relations: ['user'],
    });

    if (!session) throw new BadRequestException('Session not found');
    if (session.user.id !== userId)
      throw new BadRequestException('You cant do this action');

    session.revoked = true;

    await this.sessionsRepository.save(session);

    return { success: true, message: 'Session revoked successfully' };
  }

  async revokeAllSessions(req: Request) {
    const { userId, sessionId } = req['user'] as JwtPayload;

    if (!sessionId)
      throw new BadRequestException('Session ID not found in token');

    await this.sessionsRepository
      .createQueryBuilder()
      .update(Session)
      .set({ revoked: true })
      .where('userId = :userId', { userId })
      .andWhere('id != :sessionId', { sessionId })
      .andWhere('revoked = :revoked', { revoked: false })
      .execute();

    return {
      success: true,
      message: 'All sessions revoked except current',
    };
  }

  async cleanupSessions(dto: CleanupSessionDto) {
    if (!dto.confirm) {
      throw new BadRequestException('Confirmation required');
    }
    const NOW = new Date(Date.now());

    const sessions = await this.sessionsRepository
      .createQueryBuilder()
      .delete()
      .where('revoked = true OR expires < :NOW', { NOW })
      .execute();

    return {
      success: true,
      message: 'Sessions cleaned up',
      deletedCount: sessions.affected,
    };
  }
}
