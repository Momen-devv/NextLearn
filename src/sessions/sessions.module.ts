import { forwardRef, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SessionsController } from './sessions.controller';
import { User } from 'src/users/entities/user.entity';
import { Session } from './entities/session.entity';
import { SessionsService } from './sessions.service';
import { SharedModule } from 'src/Shared/shard.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Session, User]),
    forwardRef(() => SharedModule),
  ],
  controllers: [SessionsController],
  providers: [SessionsService],
})
export class SessionsModule {}
