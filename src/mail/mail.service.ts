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
    verificationToken: string,
  ) {
    const baseUrl = this.configService.get<string>('BASE_URL');
    const verificationUrl = `${baseUrl}/auth/verify-email/${verificationToken}`;

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
}
