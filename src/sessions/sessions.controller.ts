import {
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
import { AuthGuard } from 'src/guards/auth.guard';

@Controller('sessions')
export class SessionsController {
  constructor(private sessionsService: SessionsService) {}

  @UseGuards(AuthGuard)
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

  @UseGuards(AuthGuard)
  @Post('logout')
  @HttpCode(200)
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.sessionsService.logout(req, res);
  }

  @UseGuards(AuthGuard)
  @Post('revoke-session/:sessionId')
  @HttpCode(200)
  revokeSession(
    @Param('sessionId', new ParseUUIDPipe()) sessionId: string,
    @Req() req: Request,
  ) {
    return this.sessionsService.revokeSession(sessionId, req);
  }
}
