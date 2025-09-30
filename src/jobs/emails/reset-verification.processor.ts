import { Processor, WorkerHost } from '@nestjs/bullmq';
import { MailService } from '../../mail/mail.service';
import { Job } from 'bullmq';
import { ResendVerificationJobData } from '../interfaces';

@Processor('emailQueue', { name: 'send-reset-verification', concurrency: 3 })
export class ResetVerificationEmailProcessor extends WorkerHost {
  constructor(private mailService: MailService) {
    super();
  }

  async process(
    job: Job<ResendVerificationJobData, any, 'send-reset-verification'>,
  ) {
    const { email, firstName, verificationCode } = job.data;
    await this.mailService.sendResendVerificationEmail(
      email,
      firstName,
      verificationCode,
    );
    console.log(`Reset email sent to ${email}`);
  }

  onFailed(
    job: Job<ResendVerificationJobData, any, 'send-reset-verification'>,
    err: Error,
  ) {
    console.log(`Failed to send reset to ${job.data.email}: ${err.message}`);
  }
}
