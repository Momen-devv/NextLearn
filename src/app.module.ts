import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { dataSourceOptions } from '../db/data-source';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { MailModule } from './mail/mail.module';
import { SessionsModule } from './sessions/sessions.module';
import { SharedModule } from './Shared/shard.module';
import { UserSeederService } from './users/seeder/user.seeder.service';
import { Role } from './users/entities/roles.entity';
import { User } from './users/entities/user.entity';
import { CloudinaryModule } from './Shared/cloudinary/cloudinary.module';
import { BullModule } from '@nestjs/bullmq';
import { JobsModule } from './jobs/jobs.module';

@Module({
  imports: [
    TypeOrmModule.forRoot(dataSourceOptions),
    TypeOrmModule.forFeature([User, Role]),
    SharedModule,
    CloudinaryModule,
    ThrottlerModule.forRoot([
      {
        name: 'sensitive', // For highly sensitive routes like OTP or password reset
        ttl: 60000, // 1 min
        limit: 5,
      },
      {
        name: 'public', // For public routes like login and registration
        ttl: 10000, // 10 sec
        limit: 20,
      },
      {
        name: 'internal', // For regular internal authenticated routes
        ttl: 60000, // 1 min
        limit: 100,
      },
    ]),
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    BullModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        connection: {
          host: configService.get<string>('REDIS_HOST'),
          port: configService.get<number>('REDIS_PORT'),
          username: configService.get<string>('REDIS_USERNAME'),
          password: configService.get<string>('REDIS_PASSWORD'),
        },
        defaultJobOptions: { attempts: 3, backoff: 5000 },
      }),
      inject: [ConfigService],
    }),
    AuthModule,
    UsersModule,
    MailModule,
    SessionsModule,
    JobsModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    UserSeederService,
  ],
})
export class AppModule {}
