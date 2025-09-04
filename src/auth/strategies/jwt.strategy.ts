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
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET')!,
    });
  }

  async validate(payload: JwtPayload) {
    const session = await this.sessionsRepository.findOne({
      where: { id: payload.sessionId },
      relations: ['user', 'user.roles'],
      select: {
        id: true,
        revoked: true,
        expires: true,
        user: {
          id: true,
          isBlocked: true,
          roles: {
            name: true,
          },
        },
      },
    });

    if (!session) throw new UnauthorizedException('Session not found');
    if (session.revoked) throw new UnauthorizedException('Session revoked');
    if (session.expires && session.expires < new Date())
      throw new UnauthorizedException('Session expired');

    const user = session.user;
    if (!user || user.isBlocked)
      throw new UnauthorizedException('User blocked or not found');

    const roles = session.user.roles || [];

    return {
      userId: payload.userId,
      sessionId: payload.sessionId,
      roles: roles.map((role) => role.name),
    };
  }
}
