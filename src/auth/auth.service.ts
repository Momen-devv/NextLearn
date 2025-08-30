import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { RefreshToken } from 'src/users/entities/refresh-token.entity';
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

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    @InjectRepository(RefreshToken)
    private readonly refreshTokensRepository: Repository<RefreshToken>,
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

      const verificationCodeExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min
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
      const user = await this.ensureUserExists(verificationCode);

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
      const user = await this.usersRepository.findOne({
        where: { email: dto.email },
      });
      if (!user) throw new BadRequestException('No user found with this email');
      if (user.isEmailVerified === true)
        throw new BadRequestException('user account already verified');

      if (
        user.verificationCodeExpiresAt &&
        user.verificationCodeExpiresAt > new Date()
      )
        throw new BadRequestException(
          'A verification email has already been sent and is still valid. Please check your inbox.',
        );

      const verificationCode = this.generateVerificationCode();

      const verificationCodeExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min
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
      const user = await this.usersRepository.findOne({
        where: { email: dto.email },
      });

      if (!user)
        throw new BadRequestException(
          'there is no user with this email, try register',
        );

      if (!user.isEmailVerified)
        throw new UnauthorizedException('Email not verified');

      const isPasswordValid = await compare(dto.password, user.password);
      if (!isPasswordValid)
        throw new UnauthorizedException('Invalid email or password');
      // Genrate access token and refresh token
      const payload = { userId: user.id };
      const refreshToken = await this.jwtService.signAsync(payload, {
        expiresIn: '10d',
      });
      // Get user device
      const ua = useragent.parse(req.headers['user-agent']);
      const deviceInfo = `${ua.os?.toString() || 'Unknown OS'} - ${ua.device?.toString() || 'Unknown Device'} - ${req.ip}`;

      // Save refresh token in DB with info
      const newRefreshToken = this.refreshTokensRepository.create({
        token: refreshToken,
        user,
        expires: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000), // 10d
        device: deviceInfo,
      });
      await this.refreshTokensRepository.save(newRefreshToken);

      const payloadAccessToken = {
        userId: user.id,
        sessionId: newRefreshToken.id,
      };
      const accessToken = await this.jwtService.signAsync(payloadAccessToken, {
        expiresIn: '15m',
      });

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

      const token = await this.refreshTokensRepository.findOne({
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
        expiresIn: '15m',
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
      const user = await this.usersRepository.findOne({
        where: { email: dto.email },
      });
      if (!user)
        throw new BadRequestException('There is no user with this email');

      if (
        user.passwordResetCodeExpiresAt &&
        user.passwordResetCodeExpiresAt > new Date()
      )
        throw new BadRequestException(
          'A email has already been sent and is still valid. Please check your inbox.',
        );

      const resetCode = this.generateVerificationCode();
      const verificationCodeExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min

      user.passwordResetCode = resetCode;
      user.passwordResetCodeExpiresAt = verificationCodeExpiresAt;

      await this.usersRepository.save(user);

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
      const user = await this.usersRepository.findOne({
        where: { passwordResetCode: token },
      });
      if (!user) throw new BadRequestException('User not found');
      if (
        user.passwordResetCodeExpiresAt &&
        user.passwordResetCodeExpiresAt < new Date()
      )
        throw new BadRequestException('Token invalid or expired');

      const newPassword = await this.hashPassword(dto.password);

      user.password = newPassword;
      user.passwordResetCode = null;
      user.passwordResetCodeExpiresAt = null;
      await this.usersRepository.save(user);

      return { message: 'Password reset successful', status: 200 };
    } catch (error) {
      throw new BadRequestException('Reset password failed');
    }
  }

  async changePassword(dto: ChangePasswordDto, req: Request, res: Response) {
    try {
      const payload = req['user'];
      const user = await this.usersRepository.findOne({
        where: { id: payload.userId },
      });

      if (!user) throw new BadRequestException('User not found');
      const checkOldPass = await compare(dto.oldPassword, user.password);
      if (!checkOldPass)
        throw new BadRequestException('Old password not correct');

      const newPassword = await this.hashPassword(dto.newPassword);

      user.password = newPassword;
      await this.usersRepository.save(user);

      await this.refreshTokensRepository.update(
        { user: payload.userId },
        { revoked: true, expires: new Date(Date.now()) },
      );

      //
      const Setpayload = { userId: user.id };
      const refreshToken = await this.jwtService.signAsync(Setpayload, {
        expiresIn: '10d',
      });
      // Get user device
      const ua = useragent.parse(req.headers['user-agent']);
      const deviceInfo = `${ua.os?.toString() || 'Unknown OS'} - ${ua.device?.toString() || 'Unknown Device'} - ${req.ip}`;

      // Save refresh token in DB with info
      const newRefreshToken = this.refreshTokensRepository.create({
        token: refreshToken,
        user,
        expires: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000), // 10d
        device: deviceInfo,
      });
      await this.refreshTokensRepository.save(newRefreshToken);

      const payloadAccessToken = {
        userId: user.id,
        sessionId: newRefreshToken.id,
      };
      const accessToken = await this.jwtService.signAsync(payloadAccessToken, {
        expiresIn: '15m',
      });

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
      maxAge: 10 * 24 * 60 * 60 * 1000,
    });
  }

  private async ensureUserNotExists(email: string) {
    const user = await this.usersRepository.findOne({ where: { email } });
    if (user) throw new BadRequestException('User already exists');
  }

  private async ensureUserExists(verificationCode: string) {
    const user = await this.usersRepository.findOne({
      where: { verificationCode: verificationCode },
    });
    if (!user) throw new BadRequestException('No user found');
    return user;
  }

  private checkVerificationCode(user: Partial<User>, verificationCode: string) {
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

  private generateToken(userId: number, userRole: string): Promise<string> {
    return this.jwtService.signAsync({ userId, userRole });
  }

  private generateVerificationCode(): string {
    return uuidv4();
  }
}
