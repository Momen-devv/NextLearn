import {
  PipeTransform,
  Injectable,
  HttpException,
  HttpStatus,
} from '@nestjs/common';

@Injectable()
export class ProfileImageValidationPipe implements PipeTransform {
  private readonly maxSize = 5 * 1024 * 1024;
  private readonly allowedTypes = ['image/jpeg', 'image/png'];

  transform(file: Express.Multer.File) {
    if (!file) {
      throw new HttpException('No file uploaded', HttpStatus.BAD_REQUEST);
    }

    if (!this.allowedTypes.includes(file.mimetype)) {
      throw new HttpException(
        'Only JPEG or PNG images are allowed',
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    if (file.size > this.maxSize) {
      throw new HttpException(
        'File size exceeds 5MB limit',
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    return file;
  }
}
