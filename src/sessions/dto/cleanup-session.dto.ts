import { IsBoolean, IsDefined } from 'class-validator';

export class CleanupSessionDto {
  @IsBoolean()
  @IsDefined()
  confirm: boolean;
}
