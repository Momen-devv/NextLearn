import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { SessionsService } from './sessions.service';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from 'src/decorators/roles.decorator';
import { UserRole } from 'src/enums/user-role.enum';
import { RolesGuard } from 'src/guards/roles.guard';
import { CleanupSessionDto } from './dto/cleanup-session.dto';

@Controller('sessions')
export class SessionsController {
  constructor(private sessionsService: SessionsService) {}

  @UseGuards(AuthGuard('jwt'))
  @Get()
  @HttpCode(200)
  sessions(@Req() req: Request) {
    return this.sessionsService.sessions(req);
  }

  @Post('refresh')
  @HttpCode(200)
  refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.sessionsService.refresh(req, res);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('logout')
  @HttpCode(200)
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.sessionsService.logout(req, res);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('revoke-session/:sessionId')
  @HttpCode(200)
  revokeSession(
    @Param('sessionId', new ParseUUIDPipe()) sessionId: string,
    @Req() req: Request,
  ) {
    return this.sessionsService.revokeSession(sessionId, req);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('revoke-all-sessions')
  @HttpCode(200)
  revokeAllSessions(@Req() req: Request) {
    return this.sessionsService.revokeAllSessions(req);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(UserRole.ADMIN)
  @Delete('cleanup-sessions')
  cleanupSessions(@Body() dto: CleanupSessionDto) {
    return this.sessionsService.cleanupSessions(dto);
  }
}
