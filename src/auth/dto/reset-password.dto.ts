import { IsDefined, IsIn, IsString, Length, ValidateIf } from 'class-validator';

export class ResetPassword {
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
