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
      status: 200,
      data: { sessions },
    };
  }

  async refresh(req: Request, res: Response) {
    const refreshToken = req.cookies['refreshToken'] as string;

    if (!refreshToken) throw new UnauthorizedException('No refresh token');

    const session = await this.sessionsRepository.findOne({
      where: { token: refreshToken },
      relations: ['user'],
    });
    if (!session || session.expires < new Date() || session.revoked === true)
      throw new UnauthorizedException('Invalid refresh token');

    const payload = {
      userId: session?.user.id,
      sessionId: session?.id,
      role: session?.user.role,
    } as JwtPayload;

    const newAccessToken = await this.jwtService.signAsync(payload, {
      expiresIn: this.configService.get(
        'ACCESS_TOKEN_EXPIRATION_TIME',
      ) as string,
    });
    res.setHeader('Authorization', `Bearer ${newAccessToken}`);

    return {
      message: 'Access token refreshed',
      status: 200,
      data: {
        token: newAccessToken,
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

    return { status: 200, message: 'Logged out successfully' };
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

    return { status: 200, message: 'Session revoked successfully' };
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
}
