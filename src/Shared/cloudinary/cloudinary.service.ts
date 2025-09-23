import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { v2 as cloudinary, UploadApiResponse } from 'cloudinary';

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
    file: Express.Multer.File,
    folder: string,
    publicId: string,
  ): Promise<UploadApiResponse> {
    return new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          resource_type: 'image',
          folder: folder,
          public_id: publicId,
        },
        (error, result) => {
          if (error) reject(new Error(`Upload failed: ${error.message}`));
          else resolve(result as UploadApiResponse);
        },
      );
      uploadStream.end(file.buffer);
    });
  }

  async deleteFile(publicId: string): Promise<void> {
    await cloudinary.uploader.destroy(publicId);
  }
}
