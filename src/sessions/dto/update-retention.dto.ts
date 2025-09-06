import { IsDefined, IsNumber, Min } from 'class-validator';

export class UpdateRetentionDto {
  @IsNumber()
  @IsDefined()
  @Min(1)
  days: number;
}
