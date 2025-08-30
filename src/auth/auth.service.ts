import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User, UserRole } from 'src/users/entities/user.entity';
import { Session } from 'src/users/entities/session.entity';
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

const VERIFICATION_CODE_EXPIRATION_TIME: number = 10 * 60 * 1000; // 10 minutes
const REFRESH_TOKEN_EXPIRATION_TIME: number = 10 * 24 * 60 * 60 * 1000; // 10 days
const ACCESS_TOKEN_EXPIRATION_TIME: string = '15m';
const REFRESH_TOKEN_EXPIRATION: string = '10d';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    @InjectRepository(Session)
    private readonly sessionsRepository: Repository<Session>,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
  ) {}

  async register(dto: RegisterDto) {
    try {
      // Check if user email exist in db user
      await this.ensureUserNotExists(dto.email);

      // Hash password
      const hashedPassword = await this.hashPassword(dto.password);

      // Genrate verification code
      const verificationCode = this.generateVerificationCode();

      const verificationCodeExpiresAt = new Date(
        Date.now() + VERIFICATION_CODE_EXPIRATION_TIME,
      ); // 10 min

      // Add user in the db
      const user = await this.createUser({
        ...dto,
        password: hashedPassword,
        verificationCode,
        verificationCodeExpiresAt,
      });

      // Send email to verify account with verification code
      await this.sendVerificationMail(
        user.email,
        user.firstName,
        verificationCode,
      );

      return {
        message: 'Verification link sent, please verify your account',
        status: 201,
      };
    } catch (error) {
      throw new BadRequestException('Registration failed');
    }
  }

  // GET /auth/verify-email/:verificationCode
  async verifyEmail(verificationCode: string) {
    try {
      const user = await this.ensureUserExists(
        'verificationCode',
        verificationCode,
      );

      this.checkVerificationCode(user, verificationCode);

      await this.updateUser(user.id, {
        isEmailVerified: true,
        verificationCode: null,
        verificationCodeExpiresAt: null,
      });

      return {
        message: 'Your account verified successfully, please log in',
        status: 200,
      };
    } catch (error) {
      throw new BadRequestException('Verification failed');
    }
  }

  // post /auth/resend-verification
  async resendVerificationEmail(dto: ResendVerification) {
    try {
      const user = await this.ensureUserExists('email', dto.email);

      this.checkEmailVerificationStatus(user);

      const verificationCode = this.generateVerificationCode();

      const verificationCodeExpiresAt = new Date(
        Date.now() + VERIFICATION_CODE_EXPIRATION_TIME,
      ); // 10 min

      // Add user in the db
      await this.usersRepository.update(
        { id: user.id },
        {
          verificationCode,
          verificationCodeExpiresAt,
        },
      );

      // Send email to verify account with verification code
      await this.mailService.sendResendVerificationEmail(
        user.email,
        user.firstName,
        verificationCode,
      );

      return { message: 'Verification link resent to your email', status: 200 };
    } catch (error) {
      throw new BadRequestException('Resend verification failed');
    }
  }

  // POST /auth/login
  async login(dto: LoginDto, req: Request, res: Response) {
    try {
      const user = await this.ensureUserExists('email', dto.email);

      await this.validateLoginCredentials(user, dto);

      // Genrate access token and refresh token
      const refreshToken = await this.createRefreshToken(user.id, user.role);
      // Get user device
      const deviceInfo = this.getDeciceInfo(req);

      // Save Session with refresh token in DB with info
      const newSession = await this.createSession(
        refreshToken,
        user,
        deviceInfo,
      );

      const accessToken = await this.createRAccessToken(user.id, newSession.id);

      this.setTokens(res, accessToken, refreshToken);
      return {
        message: 'Login successful',
        status: 200,
        data: { token: accessToken },
      };
    } catch (error) {
      throw new BadRequestException('Login failed');
    }
  }
  // TO DO : but refresh with sessions
  async refresh(req: Request, res: Response) {
    try {
      const refreshToken = req.cookies['refreshToken'] as string;

      if (!refreshToken) throw new UnauthorizedException('No refresh token');

      const token = await this.sessionsRepository.findOne({
        where: { token: refreshToken },
        relations: ['user'],
      });
      if (!token || token.expires < new Date())
        throw new UnauthorizedException('Invalid refresh token');

      const payload = {
        userId: token.user.id,
        email: token.user.email,
      };
      const newAccessToken = await this.jwtService.signAsync(payload, {
        expiresIn: ACCESS_TOKEN_EXPIRATION_TIME,
      });
      res.setHeader('Authorization', `Bearer ${newAccessToken}`);

      return {
        message: 'Access token refreshed',
        status: 200,
        data: {
          token: newAccessToken,
        },
      };
    } catch (error) {
      throw new BadRequestException('refresh failed');
    }
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    try {
      const user = await this.ensureUserExists('email', dto.email);

      const resetCode = this.generateVerificationCode();

      await this.assignResetCodeToUser(user, resetCode);

      await this.mailService.sendResetPassword(
        user.email,
        user.firstName,
        resetCode,
      );

      return { message: 'Reset link sent to your email', status: 200 };
    } catch (error) {
      throw new BadRequestException('Forgot password request failed');
    }
  }

  async resetPassword(dto: ResetPassword, token: string) {
    try {
      const user = await this.ensureUserExists('passwordResetCode', token);

      this.checkPasswordResetStatus(user);

      const newPassword = await this.hashPassword(dto.password);

      await this.updateUserPasswordAfterReset(user, newPassword);

      return { message: 'Password reset successful', status: 200 };
    } catch (error) {
      throw new BadRequestException('Reset password failed');
    }
  }

  async changePassword(dto: ChangePasswordDto, req: Request, res: Response) {
    try {
      const payload = req['user'] as JwtPayload;

      const user = await this.ensureUserExists('id', payload.userId);

      await this.checkOldPasswordCorrect(dto.oldPassword, user.password);

      await this.setNewPassword(user, dto.newPassword);

      await this.sessionsRepository.update(
        { user: { id: payload.userId } },
        { revoked: true, expires: new Date(Date.now()) },
      );

      const refreshToken = await this.createRefreshToken(user.id, user.role);
      // Get user device
      const deviceInfo = this.getDeciceInfo(req);

      // Save session with refresh token in DB with info
      const newReSession = await this.createSession(
        refreshToken,
        user,
        deviceInfo,
      );

      const accessToken = await this.createRAccessToken(
        user.id,
        newReSession.id,
      );

      this.setTokens(res, accessToken, refreshToken);

      return {
        message: 'Password changed successfully',
        status: 200,
        data: { token: accessToken },
      };
    } catch (error) {
      throw new BadRequestException('Change password failed');
    }
  }

  private setTokens(res: Response, accessToken: string, refreshToken: string) {
    res.setHeader('Authorization', `Bearer ${accessToken}`);
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: REFRESH_TOKEN_EXPIRATION_TIME,
    });
  }

  private async ensureUserNotExists(email: string) {
    const user = await this.usersRepository.findOne({ where: { email } });
    if (user) throw new BadRequestException('User already exists');
  }

  private async ensureUserExists(field: string, value: string) {
    const user = await this.usersRepository.findOne({
      where: { [field]: value },
    });
    if (!user)
      throw new BadRequestException(`No user found with ${field}: ${value}`);
    return user;
  }

  private checkEmailVerificationStatus(user: User) {
    if (user.isEmailVerified === true)
      throw new BadRequestException('user account already verified');

    if (
      user.verificationCodeExpiresAt &&
      user.verificationCodeExpiresAt > new Date()
    )
      throw new BadRequestException(
        'A verification email has already been sent and is still valid. Please check your inbox.',
      );
  }

  private checkPasswordResetStatus(user: User) {
    if (
      user.passwordResetCodeExpiresAt &&
      user.passwordResetCodeExpiresAt < new Date()
    )
      throw new BadRequestException('Token invalid or expired');
  }

  private async validateLoginCredentials(user: User, dto: LoginDto) {
    if (!user.isEmailVerified)
      throw new UnauthorizedException('Email not verified');

    const isPasswordValid = await compare(dto.password, user.password);
    if (!isPasswordValid)
      throw new UnauthorizedException('Invalid email or password');
  }

  private async createRefreshToken(userId: string, role: UserRole) {
    const payload = { userId, role };
    return await this.jwtService.signAsync(payload, {
      expiresIn: REFRESH_TOKEN_EXPIRATION,
    });
  }

  private async createRAccessToken(userId: string, sessionId: string) {
    const payload = {
      userId,
      sessionId,
    };
    return await this.jwtService.signAsync(payload, {
      expiresIn: ACCESS_TOKEN_EXPIRATION_TIME,
    });
  }

  private getDeciceInfo(req: Request) {
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
      expires: new Date(Date.now() + REFRESH_TOKEN_EXPIRATION_TIME), // 10d
      device: deviceInfo,
    });
    await this.sessionsRepository.save(newSession);

    return newSession;
  }

  private async assignResetCodeToUser(user: User, resetCode: string) {
    const verificationCodeExpiresAt = new Date(
      Date.now() + VERIFICATION_CODE_EXPIRATION_TIME,
    ); // 10 min

    user.passwordResetCode = resetCode;
    user.passwordResetCodeExpiresAt = verificationCodeExpiresAt;

    await this.usersRepository.save(user);
  }

  private async updateUserPasswordAfterReset(user: User, newPassword: string) {
    user.password = newPassword;
    user.passwordResetCode = null;
    user.passwordResetCodeExpiresAt = null;
    await this.usersRepository.save(user);
  }

  private async checkOldPasswordCorrect(
    oldPassword: string,
    userPassword: string,
  ) {
    const checkOldPass = await compare(oldPassword, userPassword);
    if (!checkOldPass)
      throw new BadRequestException('Old password not correct');
  }

  private async setNewPassword(user: User, newPassword: string) {
    const newPass = await this.hashPassword(newPassword);
    user.password = newPass;
    await this.usersRepository.save(user);
  }

  private checkVerificationCode(user: User, verificationCode: string) {
    if (verificationCode !== user.verificationCode) {
      throw new BadRequestException('Invalid token');
    }

    if (
      user.verificationCodeExpiresAt &&
      user.verificationCodeExpiresAt < new Date()
    ) {
      throw new BadRequestException('Token has expired');
    }
  }

  private async createUser(data: Partial<User>): Promise<User> {
    const user = this.usersRepository.create(data);
    return await this.usersRepository.save(user);
  }

  private async updateUser(userId: string, data: Partial<User>) {
    await this.usersRepository.update({ id: userId }, data);
  }

  private async sendVerificationMail(
    email: string,
    firstName: string,
    verificationCode: string,
  ) {
    await this.mailService.sendVerificationEmail(
      email,
      firstName,
      verificationCode,
    );
  }

  private hashPassword(password: string): Promise<string> {
    return hash(password, 10);
  }

  private generateVerificationCode(): string {
    return uuidv4();
  }
}
