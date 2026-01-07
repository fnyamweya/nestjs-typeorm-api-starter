import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, MaxLength } from 'class-validator';

export class SetCustomerTierOverrideDto {
  @ApiPropertyOptional({
    description:
      'Tier code to override for this customer. Set to null/empty to clear override.',
    example: 'VIP',
  })
  @IsOptional()
  @IsString()
  @MaxLength(64)
  tierCode?: string;
}
