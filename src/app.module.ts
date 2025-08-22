import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';

@Module({
  imports: [
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
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
