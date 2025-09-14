import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import Redis from 'ioredis';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        return {
          global: true,
          secret: config.get<string>('JWT_SECRET'),
        };
      },
    }),
  ],
  providers: [
    {
      provide: 'REDIS_CLIENT',
      useFactory: (configService: ConfigService) => {
        const redis = new Redis({
          port: configService.get('REDIS_PORT'),
          host: configService.get('REDIS_HOST'),
          username: configService.get('REDIS_USERNAME'),
          password: configService.get('REDIS_PASSWORD'),
          reconnectOnError: (err) => {
            console.warn('Reconnecting due to error', err);
            return true; // Retry connection
          },
        });

        redis.on('error', (err) => {
          console.error('Redis Client Error', err);
        });

        redis.on('connect', () => {
          console.log('Connected to Redis successfully');
        });

        return redis;
      },
      inject: [ConfigService],
    },
  ],
  exports: [JwtModule, 'REDIS_CLIENT'],
})
export class SharedModule {}
