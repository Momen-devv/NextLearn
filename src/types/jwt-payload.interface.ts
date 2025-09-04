import { UserRole } from 'src/enums/user-role.enum';

export interface JwtPayload {
  userId: string;
  sessionId: string;
  roles: UserRole[];
}
