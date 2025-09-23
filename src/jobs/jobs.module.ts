import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import {
  ResetPasswordEmailProcessor,
  ResetVerificationEmailProcessor,
  VerificationEmailProcessor,
} from './emails';
import { MailModule } from 'src/mail/mail.module';

@Module({
  imports: [
    BullModule.registerQueue({
      name: 'emailQueue',
    }),
    MailModule,
  ],
  providers: [
    ResetPasswordEmailProcessor,
    ResetVerificationEmailProcessor,
    VerificationEmailProcessor,
  ],
  exports: [BullModule],
})
export class JobsModule {}
