import { User } from '../../users/entities/user.entity';
import { Role } from '../../users/entities/roles.entity';
import { UserRole } from '../../enums/user-role.enum';

export interface IUserRepository {
  findByEmail(email: string): Promise<User | null>;
  findById(id: string): Promise<User | null>;
  createUser(data: Partial<User>): Promise<User>;
  updateUser(id: string, data: Partial<User>): Promise<void>;
  saveUser(user: Partial<User>): Promise<void>;
  findRoleByName(name: UserRole): Promise<Role | null>;
}
