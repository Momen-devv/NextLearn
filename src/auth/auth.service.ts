import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User, UserRole } from 'src/users/entities/user.entity';
import { Session } from 'src/sessions/entities/session.entity';
import { Repository } from 'typeorm';
import { hash, compare } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { MailService } from 'src/mail/mail.service';
import { v4 as uuidv4 } from 'uuid';
import { ResendVerification } from './dto/resend-verification.dto';
import { LoginDto } from './dto/login.dto';
import type { Request, Response } from 'express';
import * as useragent from 'useragent';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPassword } from './dto/reset-password.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { JwtPayload } from 'src/types/jwt-payload.interface';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    @InjectRepository(Session)
    private readonly sessionsRepository: Repository<Session>,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
    private readonly configService: ConfigService,
  ) {}

  // Handles user registration, including password hashing and sending verification email
  async register(dto: RegisterDto) {
    const existingUser = await this.usersRepository.findOne({
      where: { email: dto.email },
    });
    if (existingUser) throw new BadRequestException('User already exists');

    const hashedPassword = await this.hashPassword(dto.password);
    const verificationCode = this.generateVerificationCode();
    const verificationCodeExpiresAt = new Date(
      Date.now() +
        Number(
          this.configService.get<number>('VERIFICATION_CODE_EXPIRATION_TIME'),
        ),
    );

    const user = await this.createUser({
      ...dto,
      password: hashedPassword,
      verificationCode,
      verificationCodeExpiresAt,
    });

    await this.mailService.sendVerificationEmail(
      user.email,
      user.firstName,
      verificationCode,
    );

    return {
      message: 'Verification link sent, please verify your account',
      status: 201,
    };
  }

  // Verifies email using the provided code and updates user status
  async verifyEmail(verificationCode: string) {
    const user = await this.ensureUserExists(
      'verificationCode',
      verificationCode,
    );

    if (verificationCode !== user.verificationCode)
      throw new BadRequestException('Invalid token');
    if (
      user.verificationCodeExpiresAt &&
      user.verificationCodeExpiresAt < new Date()
    ) {
      throw new BadRequestException('Token has expired');
    }

    await this.updateUser(user.id, {
      isEmailVerified: true,
      verificationCode: null,
      verificationCodeExpiresAt: null,
    });

    return {
      message: 'Your account verified successfully, please log in',
      status: 200,
    };
  }

  async resendVerificationEmail(dto: ResendVerification) {
    const user = await this.ensureUserExists('email', dto.email);

    if (user.isEmailVerified)
      throw new BadRequestException('User account already verified');
    if (
      user.verificationCodeExpiresAt &&
      user.verificationCodeExpiresAt > new Date()
    ) {
      throw new BadRequestException(
        'A verification email has already been sent and is still valid. Please check your inbox.',
      );
    }

    const verificationCode = this.generateVerificationCode();
    const verificationCodeExpiresAt = new Date(
      Date.now() +
        Number(this.configService.get('VERIFICATION_CODE_EXPIRATION_TIME')),
    );

    await this.usersRepository.update(
      { id: user.id },
      { verificationCode, verificationCodeExpiresAt },
    );

    await this.mailService.sendResendVerificationEmail(
      user.email,
      user.firstName,
      verificationCode,
    );

    return { message: 'Verification link resent to your email', status: 200 };
  }

  // Authenticates user, creates session, and sets tokens
  async login(dto: LoginDto, req: Request, res: Response) {
    const user = await this.ensureUserExists('email', dto.email);

    if (!user.isEmailVerified)
      throw new UnauthorizedException('Email not verified');
    const isPasswordValid = await compare(dto.password, user.password);
    if (!isPasswordValid)
      throw new UnauthorizedException('Invalid email or password');

    const refreshToken = await this.createRefreshToken(user.id, user.role);
    const deviceInfo = this.getDeviceInfo(req);
    const newSession = await this.createSession(refreshToken, user, deviceInfo);
    const accessToken = await this.createAccessToken(user.id, newSession.id);

    this.setTokens(res, accessToken, refreshToken);
    return {
      message: 'Login successful',
      status: 200,
      data: { token: accessToken },
    };
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    const user = await this.ensureUserExists('email', dto.email);

    const resetCode = this.generateVerificationCode();
    const resetCodeExpiresAt = new Date(
      Date.now() +
        Number(this.configService.get('VERIFICATION_CODE_EXPIRATION_TIME')),
    );

    await this.usersRepository.update(user.id, {
      passwordResetCode: resetCode,
      passwordResetCodeExpiresAt: resetCodeExpiresAt,
    });

    await this.mailService.sendResetPassword(
      user.email,
      user.firstName,
      resetCode,
    );

    return { message: 'Reset link sent to your email', status: 200 };
  }

  async resetPassword(dto: ResetPassword, token: string) {
    const user = await this.ensureUserExists('passwordResetCode', token);

    if (
      user.passwordResetCodeExpiresAt &&
      user.passwordResetCodeExpiresAt < new Date()
    ) {
      throw new BadRequestException('Token invalid or expired');
    }

    const newPassword = await this.hashPassword(dto.password);
    await this.updateUser(user.id, {
      password: newPassword,
      passwordResetCode: null,
      passwordResetCodeExpiresAt: null,
    });

    return { message: 'Password reset successful', status: 200 };
  }

  // Changes password, revokes old sessions, and creates new ones
  async changePassword(dto: ChangePasswordDto, req: Request, res: Response) {
    const payload = req['user'] as JwtPayload;
    const user = await this.ensureUserExists('id', payload.userId);

    const isOldPasswordCorrect = await compare(dto.oldPassword, user.password);
    if (!isOldPasswordCorrect)
      throw new BadRequestException('Old password not correct');

    const newHashedPassword = await this.hashPassword(dto.newPassword);
    await this.usersRepository.update(user.id, { password: newHashedPassword });

    await this.sessionsRepository.update(
      { user: { id: payload.userId } },
      { revoked: true, expires: new Date(Date.now()) },
    );

    const refreshToken = await this.createRefreshToken(user.id, user.role);
    const deviceInfo = this.getDeviceInfo(req);
    const newSession = await this.createSession(refreshToken, user, deviceInfo);
    const accessToken = await this.createAccessToken(user.id, newSession.id);

    this.setTokens(res, accessToken, refreshToken);

    return {
      message: 'Password changed successfully',
      status: 200,
      data: { token: accessToken },
    };
  }

  // Sets access token in header and refresh token in cookie
  private setTokens(res: Response, accessToken: string, refreshToken: string) {
    res.setHeader('Authorization', `Bearer ${accessToken}`);
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
      maxAge: Number(
        this.configService.get('REFRESH_TOKEN_COOKIES_EXPIRATION_TIME'),
      ),
    });
  }

  // Utility to find and ensure user exists by a given field
  private async ensureUserExists(field: string, value: string) {
    const user = await this.usersRepository.findOne({
      where: { [field]: value },
    });
    if (!user)
      throw new BadRequestException(`No user found with ${field}: ${value}`);
    return user;
  }

  private async createRefreshToken(userId: string, role: UserRole) {
    const payload = { userId, role };
    return await this.jwtService.signAsync(payload, {
      expiresIn: this.configService.get('REFRESH_TOKEN_EXPIRATION') as string,
    });
  }

  private async createAccessToken(userId: string, sessionId: string) {
    const payload = { userId, sessionId };
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

  private async createSession(
    refreshToken: string,
    user: User,
    deviceInfo: string,
  ) {
    const newSession = this.sessionsRepository.create({
      token: refreshToken,
      user,
      expires: new Date(
        Date.now() +
          Number(this.configService.get('REFRESH_TOKEN_EXPIRATION_TIME')),
      ),
      device: deviceInfo,
    });
    return await this.sessionsRepository.save(newSession);
  }

  private async updateUser(userId: string, data: Partial<User>) {
    await this.usersRepository.update({ id: userId }, data);
  }

  private async createUser(data: Partial<User>): Promise<User> {
    const user = this.usersRepository.create(data);
    return await this.usersRepository.save(user);
  }

  private hashPassword(password: string): Promise<string> {
    return hash(password, 10);
  }

  private generateVerificationCode(): string {
    return uuidv4();
  }
}
