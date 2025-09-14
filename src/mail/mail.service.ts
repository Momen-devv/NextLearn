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
    await this.mailerService.sendMail({
      to: email,
      subject: 'Verify Your Email',
      template: './verify-email.pug',
      context: {
        verificationCode,
        firstName,
      },
    });
  }

  async sendResendVerificationEmail(
    email: string,
    firstName: string,
    verificationCode: string,
  ) {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Resend Verification Email',
      template: './resend-verification.pug',
      context: {
        verificationCode,
        firstName,
      },
    });
  }

  async sendResetPassword(
    email: string,
    firstName: string,
    passwordResetCode: string,
  ) {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Reset Your Password',
      template: './reset-password.pug',
      context: {
        passwordResetCode,
        firstName,
      },
    });
  }
}
