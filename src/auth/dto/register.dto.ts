import { IsEmail, IsString, Length, IsNotEmpty } from 'class-validator';

export class RegisterDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @Length(6, 30)
  password: string;

  @IsString()
  @IsNotEmpty()
  @Length(2, 30)
  firstName: string;

  @IsString()
  @IsNotEmpty()
  @Length(2, 30)
  lastName: string;
}
