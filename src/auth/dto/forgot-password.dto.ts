import { IsEmail, IsNotEmpty } from 'class-validator';

export class forgotPasswordDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
