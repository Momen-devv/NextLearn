import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Role } from './entities/roles.entity';
import { JobsModule } from 'src/jobs/jobs.module';
import { ProfileImageValidationPipe } from 'src/pipes/profileimage-validation.pipe';

@Module({
  imports: [TypeOrmModule.forFeature([User, Role]), JobsModule],
  controllers: [UsersController],
  providers: [UsersService, ProfileImageValidationPipe],
})
export class UsersModule {}
