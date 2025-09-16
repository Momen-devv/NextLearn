import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch()
export class GlobalErrorFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const isDev = process.env.NODE_ENV === 'development';
    let message = 'Something went wrong';

    if (exception instanceof HttpException) {
      message = exception.getResponse()['message'] || message;
    }

    const errorResponse = {
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message: isDev
        ? exception instanceof HttpException
          ? exception.message
          : 'Internal server error'
        : message,
      stack: isDev
        ? exception instanceof Error
          ? exception.stack
          : undefined
        : undefined,
    };

    response.status(status).json(errorResponse);
  }
}
