import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { JwtPayload } from 'src/types/jwt-payload.interface';
import type { Request } from 'express';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { CloudinaryService } from 'src/Shared/cloudinary/cloudinary.service';
import sharp from 'sharp';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    private cloudinaryService: CloudinaryService,
  ) {}

  async getMe(req: Request) {
    const payload = req['user'] as JwtPayload;

    const user = await this.usersRepository.findOne({
      where: { id: payload.sub },
    });

    if (!user) throw new NotFoundException('User not found');

    const profileInfo = {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      profileImage: user.profileImage,
    };

    return {
      data: {
        profileInfo,
      },
    };
  }

  async updateMe(
    req: Request,
    dto: UpdateProfileDto,
    profileImage?: Express.Multer.File,
  ) {
    const payload = req['user'] as JwtPayload;

    const user = await this.usersRepository.findOne({
      where: { id: payload.sub },
    });
    if (!user) throw new NotFoundException('User not found');

    if (dto.firstName) user.firstName = dto.firstName;
    if (dto.lastName) user.lastName = dto.lastName;

    if (profileImage) {
      if (!profileImage.buffer)
        throw new BadRequestException('Invalid file format');

      try {
        const resizedBuffer = await sharp(profileImage.buffer)
          .resize(500, 500, { fit: sharp.fit.cover })
          .jpeg({ quality: 90 })
          .toBuffer();

        const resizedFile: Express.Multer.File = {
          ...profileImage,
          buffer: resizedBuffer,
          size: resizedBuffer.length,
        };

        const publicId = `user${user.id}-profile-v${Date.now()}`;
        const uploadResult = await this.cloudinaryService.uploadFile(
          resizedFile,
          'lms/users/profiles',
          publicId,
        );
        const newUrl = uploadResult.secure_url;

        if (user.profileImage) {
          const oldPublicId = this.extractPublicId(user.profileImage);
          try {
            await this.cloudinaryService.deleteFile(
              `${'lms/users/profiles'}/${oldPublicId}`,
            );
          } catch (error) {
            console.warn(
              `Failed to delete old image ${oldPublicId}: ${error.message}`,
            );
          }
        }

        user.profileImage = newUrl;
        await this.usersRepository.save(user);
      } catch (error) {
        throw new BadRequestException(`Upload failed: ${error.message}`);
      }
    } else {
      await this.usersRepository.save(user); // Save without image update
    }

    const profile = {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      profileImage: user.profileImage,
    };

    return { message: 'Profile updated', data: { profile } };
  }

  private extractPublicId(url: string): string {
    if (!url) return '';
    const urlParts = url.split('/');
    const publicIdWithExt = urlParts[urlParts.length - 1];
    const parts = publicIdWithExt.split('.');
    return parts.length > 1 ? parts[0] : publicIdWithExt;
  }
}
