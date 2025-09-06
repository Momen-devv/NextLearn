// src/user/seeder/user.seeder.service.ts
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { Role } from '../entities/roles.entity';
import * as bcrypt from 'bcrypt';
import { UserRole } from 'src/enums/user-role.enum';

@Injectable()
export class UserSeederService {
  constructor(
    @InjectRepository(User) private usersRepository: Repository<User>,
    @InjectRepository(Role) private rolesRepository: Repository<Role>,
  ) {}

  async seed() {
    const rolesToSeed = [UserRole.USER, UserRole.ADMIN, UserRole.INSTRUCTOR];
    for (const roleName of rolesToSeed) {
      const existingRole = await this.rolesRepository.findOneBy({
        name: roleName,
      });
      if (!existingRole) {
        await this.rolesRepository.save({ name: roleName });
      }
    }

    const userRole = await this.rolesRepository.findOneBy({
      name: UserRole.USER,
    });
    const adminRole = await this.rolesRepository.findOneBy({
      name: UserRole.ADMIN,
    });
    if (!userRole || !adminRole)
      throw new Error('USER or ADMIN role not found');

    const check = await this.usersRepository.findOneBy({
      email: 'test@example.com',
    });
    if (!check) {
      const user = this.usersRepository.create({
        email: 'test@example.com',
        password: await bcrypt.hash('defaultpassword', 10),
        firstName: 'Test',
        lastName: 'User',
      });

      user.roles = [userRole, adminRole];
      await this.usersRepository.save(user);
    }

    console.log('Seeding completed!');
  }
}
