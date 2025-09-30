import { Processor, WorkerHost } from '@nestjs/bullmq';
import { MailService } from '../../mail/mail.service';
import { Job } from 'bullmq';
import { ResetPasswordJobData } from '../interfaces';

@Processor('emailQueue', { name: 'send-reset-password', concurrency: 3 })
export class ResetPasswordEmailProcessor extends WorkerHost {
  constructor(private mailService: MailService) {
    super();
  }

  async process(job: Job<ResetPasswordJobData, any, 'send-reset-password'>) {
    const { email, firstName, passwordResetCode } = job.data;
    await this.mailService.sendResetPassword(
      email,
      firstName,
      passwordResetCode,
    );
    console.log(`Reset password email sent to ${email}`);
  }

  onFailed(
    job: Job<ResetPasswordJobData, any, 'send-reset-password'>,
    err: Error,
  ) {
    console.log(
      `Failed to send reset password to ${job.data.email}: ${err.message}`,
    );
  }
}
