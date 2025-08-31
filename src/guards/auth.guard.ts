import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Request } from 'express';
import { Session } from 'src/sessions/entities/session.entity';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { JwtPayload } from 'src/types/jwt-payload.interface';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    @InjectRepository(Session)
    private readonly sessionssRepository: Repository<Session>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: process.env.JWT_SECRET,
      });

      const user = await this.usersRepository.findOne({
        where: { id: payload.userId },
      });

      if (!user) throw new UnauthorizedException('User not found');
      if (user.isBlocked === true)
        throw new UnauthorizedException('Account is blocked');

      const session = await this.sessionssRepository.findOne({
        where: { id: payload.sessionId },
      });

      if (!session) throw new UnauthorizedException('Session not found');
      if (session.revoked === true)
        throw new UnauthorizedException('Session revoked, please log in');
      if (session.expires && session.expires < new Date())
        throw new UnauthorizedException('Session has expired');

      request['user'] = payload;
    } catch (error) {
      if (error instanceof Error) {
        if (error.name === 'JsonWebTokenError') {
          throw new UnauthorizedException('Invalid token');
        }
        if (error.name === 'TokenExpiredError') {
          throw new UnauthorizedException('Token has expired');
        }
      }
      throw new UnauthorizedException('Authentication failed');
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
