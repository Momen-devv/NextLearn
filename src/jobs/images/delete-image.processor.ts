import { Processor, WorkerHost } from '@nestjs/bullmq';
import { CloudinaryService } from '../../Shared/cloudinary/cloudinary.service';
import { Job } from 'bullmq';

interface DeleteImage {
  public_id: string;
  userId: string;
}

@Processor('imageQueue', { name: 'delete-image', concurrency: 3 })
export class DeleteImageProcessor extends WorkerHost {
  constructor(private cloudinaryService: CloudinaryService) {
    super();
  }

  async process(job: Job<DeleteImage, any, 'delete-image'>) {
    try {
      const { public_id, userId } = job.data;

      await this.cloudinaryService.deleteFile(public_id);

      console.log(`Deleted old image success for user: ${userId}`);
    } catch (error) {
      console.log(error);
    }
  }

  onFailed(job: Job<DeleteImage, any, 'delete-image'>, err: Error) {
    console.log(
      `Failed to delete image for user ${job.data.userId}: ${err.message}`,
    );
  }
}
