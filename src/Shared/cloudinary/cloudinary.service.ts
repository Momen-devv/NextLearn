import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { v2 as cloudinary, UploadApiResponse } from 'cloudinary';
import { UploadFile } from './interfaces';
@Injectable()
export class CloudinaryService {
  constructor(private configService: ConfigService) {
    cloudinary.config({
      cloud_name: this.configService.get('CLOUDINARY_CLOUD_NAME') as string,
      api_key: this.configService.get('CLOUDINARY_API_KEY') as string,
      api_secret: this.configService.get('CLOUDINARY_API_SECRET') as string,
    });
  }
  async uploadFile(
    buffer: Buffer,
    folder: string,
    publicId: string,
  ): Promise<UploadFile> {
    const result = await new Promise<UploadApiResponse>((resolve, reject) => {
      cloudinary.uploader
        .upload_stream(
          {
            resource_type: 'auto',
            folder: folder,
            public_id: publicId,
          },
          (error, result) => {
            if (error) reject(new Error(`Upload failed: ${error.message}`));
            else if (result) resolve(result);
            else reject(new Error('Upload failed: No result returned'));
          },
        )
        .end(buffer);
    });

    if (!result)
      throw new BadRequestException('Upload failed: No result returned!');
    return {
      secure_url: result.secure_url,
      public_id: result.public_id,
    };
  }

  async deleteFile(public_id: string): Promise<void> {
    await cloudinary.uploader.destroy(public_id);
  }
}
