import { BadRequestException, Injectable } from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { hash } from 'bcrypt';
import { randomBytes } from 'crypto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    private readonly jwtService: JwtService,
  ) {}

  async register(dto: RegisterDto) {
    // Check if user email exist in db user
    await this.ensureUserNotExists(dto.email);

    // Hash password
    const hashedPassword = await this.hashPassword(dto.password);

    // Genrate verification code
    const verificationCode = this.generateVerificationCode();

    // Add user in the db
    const user = await this.createUser({
      ...dto,
      password: hashedPassword,
      verificationCode,
    });
    // Create jwt for user
    const token = await this.generateToken(user.id, user.role);

    return token;

    // Send email to verify account with verification code
  }

  // GET /auth/verify-email/:userId/:verificationCode
  // verify(){}

  private async ensureUserNotExists(email: string) {
    const user = await this.usersRepository.findOne({ where: { email } });
    if (user) throw new BadRequestException('User already exists');
  }

  private async createUser(data: Partial<User>): Promise<User> {
    const user = this.usersRepository.create(data);
    return await this.usersRepository.save(user);
  }

  private hashPassword(password: string): Promise<string> {
    return hash(password, 10);
  }

  private generateToken(userId: number, userRole: string): Promise<string> {
    return this.jwtService.signAsync({ userId, userRole });
  }

  private generateVerificationCode(): string {
    return randomBytes(32).toString('hex');
  }
}
