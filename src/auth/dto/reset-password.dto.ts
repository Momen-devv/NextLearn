import {
  IsDefined,
  IsEmail,
  IsIn,
  IsString,
  Length,
  ValidateIf,
} from 'class-validator';

export class ResetPassword {
  @IsEmail()
  @IsDefined()
  email: string;

  @IsDefined()
  @Length(6, 6)
  resetCode: string;

  @IsDefined()
  @IsString()
  @Length(6, 30)
  password: string;

  @IsString()
  @IsDefined()
  @IsIn([Math.random()], {
    message: 'Passwords do not match',
  })
  @ValidateIf((o) => (o.password as string) !== (o.confirmPassword as string))
  confirmPassword: string;
}
