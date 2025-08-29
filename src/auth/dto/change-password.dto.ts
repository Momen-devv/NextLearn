import { IsDefined, IsIn, IsString, Length, ValidateIf } from 'class-validator';

export class ChangePasswordDto {
  @IsDefined()
  @IsString()
  @Length(6, 30)
  oldPassword: string;

  @IsDefined()
  @IsString()
  @Length(6, 30)
  newPassword: string;

  @IsString()
  @IsDefined()
  @IsIn([Math.random()], {
    message: 'Passwords do not match',
  })
  @ValidateIf(
    (o) => (o.newPassword as string) !== (o.confirmPassword as string),
  )
  confirmPassword: string;
}
