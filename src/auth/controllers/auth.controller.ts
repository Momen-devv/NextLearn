import {
  Body,
  Controller,
  Get,
  Post,
  Res,
  Req,
  UseGuards,
  HttpCode,
} from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import {
  RegisterDto,
  ResendVerification,
  LoginDto,
  ForgotPasswordDto,
  ResetPassword,
  ChangePasswordDto,
  VerifyEmailDto,
} from '../dto';
import type { Request, Response } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { Throttle } from '@nestjs/throttler';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Throttle({ public: {} })
  @Post('register')
  @HttpCode(201)
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Throttle({ sensitive: {} })
  @Get('verify-email')
  @HttpCode(200)
  verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.authService.verifyEmail(dto);
  }

  @Throttle({ sensitive: {} })
  @Post('resend-verification')
  @HttpCode(200)
  resendVerification(@Body() dto: ResendVerification) {
    return this.authService.resendVerificationEmail(dto);
  }

  @Throttle({ public: {} })
  @Post('login')
  @HttpCode(200)
  login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.login(dto, req, res);
  }

  @Throttle({ sensitive: {} })
  @Post('forgot-password')
  @HttpCode(200)
  forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto);
  }

  @Throttle({ sensitive: {} })
  @Post('reset-password')
  @HttpCode(200)
  resetPassword(@Body() dto: ResetPassword) {
    return this.authService.resetPassword(dto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Throttle({ sensitive: {} })
  @Post('change-password')
  @HttpCode(200)
  changePassword(
    @Body() dto: ChangePasswordDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.changePassword(dto, req, res);
  }
}
