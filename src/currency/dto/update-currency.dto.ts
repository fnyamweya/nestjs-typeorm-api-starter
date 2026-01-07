import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsInt, IsOptional, IsString, Max, Min } from 'class-validator';

export class UpdateCurrencyDto {
  @ApiPropertyOptional({ description: 'Display symbol', example: 'KSh' })
  @IsOptional()
  @IsString()
  symbol?: string;

  @ApiPropertyOptional({
    description: 'Decimal precision (minor unit exponent)',
    example: 2,
  })
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(8)
  precision?: number;
}
