import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../../types/jwt-payload.interface';
import Redis from 'ioredis';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject('REDIS_CLIENT') private redisClient: Redis,
    private configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET')!,
    });
  }

  async validate(payload: JwtPayload) {
    const { sub: userId, sid: sessionId, roles } = payload;
    const sessionKey = `session:${userId}:${sessionId}`;

    const session = await this.redisClient.hgetall(sessionKey);

    if (
      !session ||
      session.revoked === 'true' ||
      new Date(session.refreshExpiresAt) < new Date()
    ) {
      throw new UnauthorizedException('Session invalid or expired');
    }

    return { sub: userId, sid: sessionId, roles: roles };
  }
}
