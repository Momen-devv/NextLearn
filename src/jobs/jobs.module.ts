import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import {
  ResetPasswordEmailProcessor,
  ResetVerificationEmailProcessor,
  VerificationEmailProcessor,
} from './emails';
import { DeleteImageProcessor } from './images';
import { MailModule } from 'src/mail/mail.module';
import { User } from 'src/users/entities/user.entity';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
    BullModule.registerQueue(
      {
        name: 'emailQueue',
      },
      {
        name: 'imageQueue',
      },
    ),
    MailModule,
    TypeOrmModule.forFeature([User]),
  ],
  providers: [
    ResetPasswordEmailProcessor,
    ResetVerificationEmailProcessor,
    VerificationEmailProcessor,
    DeleteImageProcessor,
  ],
  exports: [BullModule],
})
export class JobsModule {}
