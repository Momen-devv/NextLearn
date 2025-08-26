import { IsEmail, IsNotEmpty } from 'class-validator';

export class ResendVerification {
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
