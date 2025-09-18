import {
  Body,
  Controller,
  Get,
  Patch,
  Req,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { AuthGuard } from '@nestjs/passport';
import type { Request } from 'express';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @UseGuards(AuthGuard('jwt'))
  @Get('me')
  GetMe(@Req() req: Request) {
    return this.usersService.getMe(req);
  }

  @UseGuards(AuthGuard('jwt'))
  @UseInterceptors(
    FileInterceptor('profileImage', { storage: memoryStorage() }),
  )
  @Patch('me')
  updateMe(
    @Req() req: Request,
    @Body() dto: UpdateProfileDto,
    @UploadedFile() profileImage: Express.Multer.File,
  ) {
    return this.usersService.updateMe(req, dto, profileImage);
  }
}
