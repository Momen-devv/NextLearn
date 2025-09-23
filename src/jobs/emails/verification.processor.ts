import { Processor, WorkerHost } from '@nestjs/bullmq';
import { MailService } from '../../mail/mail.service';
import { Job } from 'bullmq';
import { VerificationJobData } from '../interfaces';

@Processor('emailQueue', { name: 'send-verification' })
export class VerificationEmailProcessor extends WorkerHost {
  constructor(private mailService: MailService) {
    super();
  }

  async process(job: Job<VerificationJobData, any, 'send-verification'>) {
    const { email, firstName, verificationCode } = job.data;
    await this.mailService.sendVerificationEmail(
      email,
      firstName,
      verificationCode,
    );
    console.log(`Verification email sent to ${email}`);
  }

  onFailed(
    job: Job<VerificationJobData, any, 'send-verification'>,
    err: Error,
  ) {
    console.log(
      `Failed to send verification to ${job.data.email}: ${err.message}`,
    );
  }
}
