import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsInt,
  IsOptional,
  IsString,
  Matches,
  Max,
  Min,
} from 'class-validator';

export class CreateCurrencyDto {
  @ApiProperty({
    description: 'ISO 4217 currency code (3 letters)',
    example: 'KES',
  })
  @IsString()
  @Matches(/^[A-Za-z]{3}$/)
  code: string;

  @ApiPropertyOptional({ description: 'Display symbol', example: 'KSh' })
  @IsOptional()
  @IsString()
  symbol?: string;

  @ApiPropertyOptional({
    description: 'Decimal precision (minor unit exponent)',
    default: 2,
    example: 2,
  })
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(8)
  precision?: number;
}
