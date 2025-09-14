import { UserRole } from 'src/enums/user-role.enum';

export interface JwtPayload {
  sub: string;
  sid: string;
  roles: UserRole[];
}
