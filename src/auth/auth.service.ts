import { BadRequestException, Injectable } from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { hash } from 'bcrypt';
import { randomBytes } from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { MailService } from 'src/mail/mail.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly mailServics: MailService,
  ) {}

  async register(dto: RegisterDto) {
    // Check if user email exist in db user
    await this.ensureUserNotExists(dto.email);

    // Hash password
    const hashedPassword = await this.hashPassword(dto.password);

    // Genrate verification code
    const verificationCode = this.generateVerificationCode();

    const verificationCodeExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min

    // Add user in the db
    const user = await this.createUser({
      ...dto,
      password: hashedPassword,
      verificationCode,
      verificationCodeExpiresAt,
    });

    // Send email to verify account with verification code
    await this.mailServics.sendVerificationEmail(
      user.email,
      user.firstName,
      verificationCode,
    );

    return 'verification link send your email please verify your account';
  }

  // GET /auth/verify-email/:verificationCode
  async verifyEmail(verificationCode: string) {
    const user = await this.usersRepository.findOne({
      where: { verificationCode: verificationCode },
    });

    if (!user) throw new BadRequestException('No user found');

    if (verificationCode !== user.verificationCode) {
      throw new BadRequestException('Invalid token');
    }

    if (
      user.verificationCodeExpiresAt &&
      user.verificationCodeExpiresAt < new Date()
    ) {
      throw new BadRequestException('Token has expired');
    }

    await this.usersRepository.update(
      { id: user.id },
      {
        isEmailVerified: true,
        verificationCode: null,
        verificationCodeExpiresAt: null,
      },
    );

    return 'Your account verified successfully';
  }

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
