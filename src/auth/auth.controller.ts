import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  ParseUUIDPipe,
  Res,
  Req,
  UseGuards,
  HttpCode,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { ResendVerification } from './dto/resend-verification.dto';
import { LoginDto } from './dto/login.dto';
import type { Request, Response } from 'express';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPassword } from './dto/reset-password.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
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
  @Get('verify-email/:verificationCode')
  @HttpCode(200)
  verifyEmail(
    @Param('verificationCode', new ParseUUIDPipe())
    verificationCode: string,
  ) {
    return this.authService.verifyEmail(verificationCode);
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
  @Post('reset-password/:token')
  @HttpCode(200)
  resetPassword(
    @Body() dto: ResetPassword,
    @Param('token', new ParseUUIDPipe()) token,
  ) {
    return this.authService.resetPassword(dto, token);
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
