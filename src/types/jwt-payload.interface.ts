import { UserRole } from '../users/entities/user.entity';
export interface JwtPayload {
  userId: string;
  sessionId: string;
  role: UserRole;
}
