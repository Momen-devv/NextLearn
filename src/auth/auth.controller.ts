import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Get('verify-email/:userId/:verificationToken')
  verifyEmail(@Param('verificationCode') verificationToken: string) {
    return this.authService.verifyEmail(verificationToken);
  }
}
