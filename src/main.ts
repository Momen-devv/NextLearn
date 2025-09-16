import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { UserSeederService } from './users/seeder/user.seeder.service';
import { GlobalErrorFilter } from './filters/global-error.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalFilters(new GlobalErrorFilter());

  const seeder = app.get(UserSeederService);
  await seeder.seed();
  // Apply Middlewares
  app.use(cookieParser());
  app.use(helmet());

  // Cors Policy
  app.enableCors();

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
