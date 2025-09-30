import {
  BadRequestException,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  RegisterDto,
  LoginDto,
  ForgotPasswordDto,
  ResetPassword,
  ResendVerification,
  ChangePasswordDto,
  VerifyEmailDto,
} from '../dto';
import { UserRole } from 'src/enums/user-role.enum';
import { hash, compare } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import type { Request, Response } from 'express';
import * as useragent from 'useragent';
import { JwtPayload } from 'src/types/jwt-payload.interface';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import Redis from 'ioredis';
import { Queue } from 'bullmq';
import { InjectQueue } from '@nestjs/bullmq';
import { UserRepository } from '../repositories';
import type { IUserRepository } from '../interfaces';

@Injectable()
export class AuthService {
  constructor(
    @Inject(UserRepository) private readonly userRepository: IUserRepository,
    @Inject('REDIS_CLIENT') private redisClient: Redis,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    @InjectQueue('emailQueue') private emailQueue: Queue,
  ) {}

  // Handles user registration, including password hashing and sending verification email
  async register(dto: RegisterDto) {
    const existingUser = await this.userRepository.findByEmail(dto.email);

    if (existingUser) throw new BadRequestException('User already exists');

    const hashedPassword = await this.hashPassword(dto.password);
    const verificationCode = this.generateVerificationCode();

    const user = await this.userRepository.createUser({
      ...dto,
      password: hashedPassword,
    });

    await this.redisClient.setex(`otp:email:${user.id}`, 300, verificationCode); // 5 min

    await this.emailQueue.add('send-verification', {
      email: user.email,
      firstName: user.firstName,
      verificationCode: verificationCode,
    });

    return {
      message: 'Verification link sent, please verify your account',
      status: 201,
    };
  }

  // Verifies email using the provided code and updates user status
  async verifyEmail(dto: VerifyEmailDto) {
    const user = await this.userRepository.findByEmail(dto.email);
    if (!user) throw new BadRequestException('No user found with this email');

    if (user.isEmailVerified)
      throw new BadRequestException('User account already verified');

    const storedOtp = await this.redisClient.get(`otp:email:${user.id}`);
    if (!storedOtp || storedOtp !== dto.verificationCode) {
      throw new UnauthorizedException('Invalid or expired verification code');
    }

    // Cleanup OTP
    await this.redisClient.del(`otp:email:${user.id}`);

    user.isEmailVerified = true;

    const userRole = await this.userRepository.findRoleByName(UserRole.USER);
    if (userRole) {
      user.roles = user.roles || [];
      if (!user.roles.some((r) => r.name === UserRole.USER)) {
        user.roles.push(userRole);
      }
    }

    await this.userRepository.saveUser(user);

    return {
      message: 'Your account verified successfully, please log in',
      status: 200,
    };
  }

  async resendVerificationEmail(dto: ResendVerification) {
    const user = await this.userRepository.findByEmail(dto.email);
    if (!user) throw new BadRequestException('No user found with this email');

    if (user.isEmailVerified)
      throw new BadRequestException('User account already verified');

    const verificationCode = this.generateVerificationCode();

    await this.redisClient.setex(`otp:email:${user.id}`, 300, verificationCode); // 5 min

    await this.emailQueue.add('send-reset-verification', {
      email: user.email,
      firstName: user.firstName,
      verificationCode: verificationCode,
    });

    return { message: 'Verification link resent to your email', status: 200 };
  }

  // Authenticates user, creates session, and sets tokens
  async login(dto: LoginDto, req: Request, res: Response) {
    const user = await this.userRepository.findByEmail(dto.email);
    if (!user) throw new BadRequestException('No user found with this email');

    if (!user.isEmailVerified)
      throw new UnauthorizedException('Email not verified');

    if (user.isBlocked) throw new UnauthorizedException('User is blocked');

    const isPasswordValid = await compare(dto.password, user.password);
    if (!isPasswordValid)
      throw new UnauthorizedException('Invalid email or password');

    const refreshToken = crypto.randomBytes(16).toString('hex');

    const deviceInfo = this.getDeviceInfo(req);

    const sessionId = crypto.randomUUID();

    const accessToken = await this.createAccessToken(
      user.id,
      sessionId,
      user.roles.map((role) => role.name),
    );
    const sessionKey = `session:${user.id}:${sessionId}`;

    await this.redisClient.hset(
      sessionKey,
      'refreshToken',
      refreshToken,
      'deviceInfo',
      deviceInfo,
      'refreshExpiresAt',
      new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      'revoked',
      'false',
      'createdAt',
      new Date().toISOString(),
    );
    await this.redisClient.expire(sessionKey, 2592000); // 30 days

    this.setTokens(res, accessToken, refreshToken);

    return {
      message: 'Login successful',
      status: 200,
      data: {
        accessToken: accessToken,
        refreshToken: refreshToken,
      },
    };
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    const user = await this.userRepository.findByEmail(dto.email);
    if (!user) throw new NotFoundException('No user found with this email');

    const resetCode = this.generateVerificationCode();

    await this.redisClient.setex(`reset:email:${user.id}`, 900, resetCode);

    await this.emailQueue.add('send-reset-password', {
      email: user.email,
      firstName: user.firstName,
      passwordResetCode: resetCode,
    });

    return { message: 'Reset link sent to your email', status: 200 };
  }

  async resetPassword(dto: ResetPassword) {
    const user = await this.userRepository.findByEmail(dto.email);
    if (!user) throw new NotFoundException('No user found with this email');

    const storedResetCode = await this.redisClient.get(
      `reset:email:${user.id}`,
    );
    if (!storedResetCode || storedResetCode !== dto.resetCode) {
      throw new BadRequestException('Invalid or expired reset code');
    }

    const newPassword = await this.hashPassword(dto.password);

    await this.userRepository.updateUser(user.id, {
      password: newPassword,
    });

    // Cleanup Redis
    await this.redisClient.del(`reset:email:${user.id}`);

    return { message: 'Password reset successful', status: 200 };
  }

  // Changes password, revokes old sessions, and creates new ones
  async changePassword(dto: ChangePasswordDto, req: Request, res: Response) {
    const payload = req['user'] as JwtPayload;
    const user = await this.userRepository.findById(payload.sub);
    if (!user) throw new NotFoundException('No user found with this ID');

    const isOldPasswordCorrect = await compare(dto.oldPassword, user.password);
    if (!isOldPasswordCorrect)
      throw new BadRequestException('Old password not correct');

    const newHashedPassword = await this.hashPassword(dto.newPassword);
    await this.userRepository.updateUser(user.id, {
      password: newHashedPassword,
    });

    // Revoke all sessions in Redis
    const allSessionKeys = await this.redisClient.keys(`session:${user.id}:*`);
    await Promise.all(
      allSessionKeys.map((key) =>
        this.redisClient.hset(key, 'revoked', 'true'),
      ),
    );

    // Create new session
    const refreshToken = crypto.randomBytes(16).toString('hex');
    const deviceInfo = this.getDeviceInfo(req);
    const sessionId = crypto.randomUUID();
    await this.redisClient.hset(`session:${user.id}:${sessionId}`, [
      'refreshToken',
      refreshToken,
      'deviceInfo',
      deviceInfo,
      'refreshExpiresAt',
      new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      'revoked',
      'false',
      'createdAt',
      new Date().toISOString(),
    ]);

    await this.redisClient.expire(
      `session:${user.id}:${sessionId}`,
      30 * 24 * 60 * 60,
    ); // 30 days

    const accessToken = await this.createAccessToken(
      user.id,
      sessionId,
      payload.roles,
    );

    this.setTokens(res, accessToken, refreshToken);

    return {
      message: 'Password changed successfully',
      status: 200,
      data: { accessToken: accessToken, refreshToken: refreshToken },
    };
  }

  // Sets access token in header and refresh token in cookie
  private setTokens(res: Response, accessToken: string, refreshToken: string) {
    res.setHeader('Authorization', `Bearer ${accessToken}`);
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: Number(
        this.configService.get('REFRESH_TOKEN_COOKIES_EXPIRATION_TIME'),
      ),
    });
  }

  private async createAccessToken(
    userId: string,
    sessionId: string,
    roles: UserRole[],
  ) {
    const payload = { sub: userId, sid: sessionId, roles };
    return await this.jwtService.signAsync(payload, {
      expiresIn: this.configService.get(
        'ACCESS_TOKEN_EXPIRATION_TIME',
      ) as string,
    });
  }

  // Extracts device info from request headers
  private getDeviceInfo(req: Request) {
    const ua = useragent.parse(req.headers['user-agent']);
    return `${ua.os?.toString() || 'Unknown OS'} - ${ua.device?.toString() || 'Unknown Device'} - ${req.ip}`;
  }

  private hashPassword(password: string): Promise<string> {
    return hash(password, 10);
  }

  private generateVerificationCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }
}
