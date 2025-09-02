import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../../types/jwt-payload.interface';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { Session } from '../../sessions/entities/session.entity';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    @InjectRepository(Session)
    private readonly sessionsRepository: Repository<Session>,
    private configService: ConfigService,
  ) {
    const secret = configService.get<string>('JWT_SECRET')!;

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: secret,
    });
  }

  async validate(payload: JwtPayload) {
    const result = await this.usersRepository
      .createQueryBuilder('user')
      .leftJoinAndSelect('user.sessions', 'session')
      .where('user.id = :userId', { userId: payload.userId })
      .andWhere('session.id = :sessionId', { sessionId: payload.sessionId })
      .getOne();

    if (!result || result.isBlocked) throw new UnauthorizedException();
    const session = result.sessions?.find((s) => s.id === payload.sessionId);
    if (
      !session ||
      session.revoked ||
      (session.expires && session.expires < new Date())
    )
      throw new UnauthorizedException();
    console.log(payload, result.roles);
    return {
      userId: payload.userId,
      sessionId: payload.sessionId,
      roles: result.roles,
    };
  }
}
