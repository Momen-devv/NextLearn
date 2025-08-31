import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  constructor(
    private readonly mailerService: MailerService,
    private readonly configService: ConfigService,
  ) {}

  async sendVerificationEmail(
    email: string,
    firstName: string,
    verificationCode: string,
  ) {
    const baseUrl = this.configService.get<string>('BASE_URL');
    const verificationUrl = `${baseUrl}/auth/verify-email/${verificationCode}`;

    await this.mailerService.sendMail({
      to: email,
      subject: 'Verify Your Email',
      template: './verify-email.pug',
      context: {
        verificationUrl,
        firstName,
      },
    });
  }

  async sendResendVerificationEmail(
    email: string,
    firstName: string,
    verificationCode: string,
  ) {
    const baseUrl = this.configService.get<string>('BASE_URL');
    const verificationUrl = `${baseUrl}/auth/verify-email/${verificationCode}`;

    await this.mailerService.sendMail({
      to: email,
      subject: 'Resend Verification Email',
      template: './resend-verification.pug',
      context: {
        verificationUrl,
        firstName,
      },
    });
  }

  async sendResetPassword(
    email: string,
    firstName: string,
    passwordResetCode: string,
  ) {
    const baseUrl = this.configService.get<string>('BASE_URL');
    const resetUrl = `${baseUrl}/auth/reset-password/${passwordResetCode}`;

    await this.mailerService.sendMail({
      to: email,
      subject: 'Reset Your Password',
      template: './reset-password.pug',
      context: {
        resetUrl,
        firstName,
      },
    });
  }
}
