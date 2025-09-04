import { Injectable } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Session } from './entities/session.entity';

@Injectable()
export class SessionsCronService {
  constructor(
    @InjectRepository(Session)
    private sessionsRepository: Repository<Session>,
  ) {}

  @Cron(CronExpression.EVERY_WEEK, {
    name: 'cleanupSessions',
    timeZone: 'Africa/Cairo',
  })
  async cleanExpiredSessions() {
    const now = new Date();

    const expiredSessions = await this.sessionsRepository
      .createQueryBuilder('session')
      .where('session.expires < :now', { now })
      .orWhere('session.revoked = :revoked', {
        revoked: true,
      })
      .getMany();

    if (expiredSessions.length > 0) {
      await this.sessionsRepository.remove(expiredSessions);
      console.log(
        `Cleaned ${expiredSessions.length} expired/revoked sessions at ${now}`,
      );
    } else {
      console.log(`No sessions to clean at ${now}`);
    }
  }
}
