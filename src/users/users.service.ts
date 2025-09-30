import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { JwtPayload } from 'src/types/jwt-payload.interface';
import type { Request } from 'express';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { CloudinaryService } from 'src/Shared/cloudinary/cloudinary.service';
import { Queue } from 'bullmq';
import { InjectQueue } from '@nestjs/bullmq';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    @InjectQueue('imageQueue') private imageQueue: Queue,
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
      profilePictureUrl: user.profilePictureUrl,
    };

    return {
      data: {
        profileInfo,
      },
    };
  }

  async updateProfile(req: Request, dto: UpdateProfileDto) {
    const payload = req['user'] as JwtPayload;

    const user = await this.usersRepository.findOne({
      where: { id: payload.sub },
    });
    if (!user) throw new NotFoundException('User not found');

    if (dto.firstName) user.firstName = dto.firstName;
    if (dto.lastName) user.lastName = dto.lastName;

    await this.usersRepository.save(user);

    const profile = {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
    };

    return { message: 'Profile updated', data: { profile } };
  }

  async updateProfilePicture(req: Request, profileImage: Express.Multer.File) {
    const payload = req['user'] as JwtPayload;

    const user = await this.usersRepository.findOne({
      where: { id: payload.sub },
      select: ['id', 'profilePictureUrl', 'publicId'],
    });
    if (!user) throw new NotFoundException('User not found');

    const publicId = `${user.id}-profile-v${Date.now()}`;
    const { secure_url, public_id } = await this.cloudinaryService.uploadFile(
      profileImage.buffer,
      'lms/users/profiles',
      publicId,
    );

    if (user.publicId) {
      try {
        await this.imageQueue.add(
          'delete-image',
          {
            public_id: user.publicId,
            userId: user.id,
          },
          { attempts: 3, backoff: 5000 },
        );
      } catch (error) {
        console.log(error);
      }
    }

    await this.usersRepository.update(user.id, {
      profilePictureUrl: secure_url,
      publicId: public_id,
    });

    return {
      message: 'Profile picture updating',
      data: { updatedProfilePictureUrl: secure_url },
    };
  }
}
