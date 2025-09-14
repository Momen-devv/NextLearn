import {
  Body,
  Controller,
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
import { Throttle } from '@nestjs/throttler';

@Controller('sessions')
export class SessionsController {
  constructor(private sessionsService: SessionsService) {}

  @Throttle({ public: {} })
  @UseGuards(AuthGuard('jwt'))
  @Get()
  @HttpCode(200)
  sessions(@Req() req: Request) {
    return this.sessionsService.sessions(req);
  }

  @Throttle({ public: {} })
  @Post('refresh')
  @HttpCode(200)
  refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.sessionsService.refresh(req, res);
  }

  @Throttle({ public: {} })
  @UseGuards(AuthGuard('jwt'))
  @Post('logout')
  @HttpCode(200)
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.sessionsService.logout(req, res);
  }

  @Throttle({ public: {} })
  @UseGuards(AuthGuard('jwt'))
  @Post('revoke-session/:sessionId')
  @HttpCode(200)
  revokeSession(
    @Param('sessionId', new ParseUUIDPipe()) sessionId: string,
    @Req() req: Request,
  ) {
    return this.sessionsService.revokeSession(sessionId, req);
  }

  @Throttle({ public: {} })
  @UseGuards(AuthGuard('jwt'))
  @Post('revoke-all-sessions')
  @HttpCode(200)
  revokeAllSessions(@Req() req: Request) {
    return this.sessionsService.revokeAllSessions(req);
  }
}
