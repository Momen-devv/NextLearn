import { BadRequestException, Injectable } from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { hash } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { MailService } from 'src/mail/mail.service';
import { v4 as uuidv4 } from 'uuid';
import { ResendVerification } from './dto/resend-verification.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
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
    await this.sendVerificationMail(
      user.email,
      user.firstName,
      verificationCode,
    );

    return {
      message: 'verification link send your email please verify your account',
    };
  }

  // GET /auth/verify-email/:verificationCode
  async verify(verificationCode: string) {
    const user = await this.ensureUserExists(verificationCode);

    this.checkVerificationCode(user, verificationCode);

    await this.updateUser(user.id, {
      isEmailVerified: true,
      verificationCode: null,
      verificationCodeExpiresAt: null,
    });

    return { message: 'Your account verified successfully, please log in' };
  }

  // post /auth/resend-verification
  async resendVerificationEmail(dto: ResendVerification) {
    const user = await this.usersRepository.findOne({
      where: { email: dto.email },
    });
    if (!user) throw new BadRequestException('No user found with this email');
    if (user.isEmailVerified === true)
      throw new BadRequestException('user account already verified');

    if (
      user.verificationCodeExpiresAt &&
      user.verificationCodeExpiresAt > new Date()
    )
      throw new BadRequestException(
        'A verification email has already been sent and is still valid. Please check your inbox.',
      );

    const verificationCode = this.generateVerificationCode();

    const verificationCodeExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min
    // Add user in the db
    await this.usersRepository.update(
      { id: user.id },
      {
        verificationCode,
        verificationCodeExpiresAt,
      },
    );

    // Send email to verify account with verification code
    await this.mailService.sendResendVerificationEmail(
      user.email,
      user.firstName,
      verificationCode,
    );

    return { message: 'Verification link resent to your email' };
  }

  // POST /auth/login

  private async ensureUserNotExists(email: string) {
    const user = await this.usersRepository.findOne({ where: { email } });
    if (user) throw new BadRequestException('User already exists');
  }

  private async ensureUserExists(verificationCode: string) {
    const user = await this.usersRepository.findOne({
      where: { verificationCode: verificationCode },
    });
    if (!user) throw new BadRequestException('No user found');
    return user;
  }

  private checkVerificationCode(user: Partial<User>, verificationCode: string) {
    console.log(verificationCode, user.verificationCode);
    if (verificationCode !== user.verificationCode) {
      throw new BadRequestException('Invalid token');
    }

    if (
      user.verificationCodeExpiresAt &&
      user.verificationCodeExpiresAt < new Date()
    ) {
      throw new BadRequestException('Token has expired');
    }
  }

  private async createUser(data: Partial<User>): Promise<User> {
    const user = this.usersRepository.create(data);
    return await this.usersRepository.save(user);
  }

  private async updateUser(userId: string, data: Partial<User>) {
    await this.usersRepository.update({ id: userId }, data);
  }

  private async sendVerificationMail(
    email: string,
    firstName: string,
    verificationCode: string,
  ) {
    await this.mailService.sendVerificationEmail(
      email,
      firstName,
      verificationCode,
    );
  }

  private hashPassword(password: string): Promise<string> {
    return hash(password, 10);
  }

  private generateToken(userId: number, userRole: string): Promise<string> {
    return this.jwtService.signAsync({ userId, userRole });
  }

  private generateVerificationCode(): string {
    return uuidv4();
  }
}
