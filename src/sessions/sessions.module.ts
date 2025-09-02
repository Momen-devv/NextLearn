import { forwardRef, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SessionsController } from './sessions.controller';
import { User } from 'src/users/entities/user.entity';
import { Session } from './entities/session.entity';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { SessionsService } from './sessions.service';
import { PassportModule } from '@nestjs/passport';
import { SharedModule } from 'src/Shared/shard.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Session, User]),
    forwardRef(() => SharedModule),
    // JwtModule,
    // PassportModule,
    // JwtModule.registerAsync({
    //   inject: [ConfigService],
    //   useFactory: (config: ConfigService) => {
    //     return {
    //       global: true,
    //       secret: config.get<string>('JWT_SECRET'),
    //     };
    //   },
    // }),
  ],
  controllers: [SessionsController],
  providers: [SessionsService],
})
export class SessionsModule {}
