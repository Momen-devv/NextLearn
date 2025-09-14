import { forwardRef, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SessionsController } from './sessions.controller';
import { User } from 'src/users/entities/user.entity';
import { SessionsService } from './sessions.service';
import { SharedModule } from 'src/Shared/shard.module';
import Redis from 'ioredis';
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [TypeOrmModule.forFeature([User]), forwardRef(() => SharedModule)],
  controllers: [SessionsController],
  providers: [SessionsService],
})
export class SessionsModule {}
