import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  ParseUUIDPipe,
  Res,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { ResendVerification } from './dto/resend-verification.dto';
import { LoginDto } from './dto/login.dto';
import type { Request, Response } from 'express';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPassword } from './dto/reset-password.dto';
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Get('verify-email/:verificationCode')
  verifyEmail(
    @Param('verificationCode', new ParseUUIDPipe())
    verificationCode: string,
  ) {
    return this.authService.verifyEmail(verificationCode);
  }

  @Post('resend-verification')
  resendVerification(@Body() dto: ResendVerification) {
    return this.authService.resendVerificationEmail(dto);
  }

  @Post('login')
  login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.login(dto, req, res);
  }

  @Post('refresh')
  refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.authService.refresh(req, res);
  }

  @Post('forgot-password')
  forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto);
  }

  @Post('reset-password/:token')
  resetPassword(
    @Body() dto: ResetPassword,
    @Param('token', new ParseUUIDPipe()) token,
  ) {
    return this.authService.resetPassword(dto, token);
  }
}
