import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsDateString,
  IsInt,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Min,
} from 'class-validator';

export class CreateProductPriceDto {
  @ApiProperty({ description: 'Price list id', example: 'uuid' })
  @IsString()
  @IsNotEmpty()
  priceListId: string;

  @ApiProperty({ description: 'Unit price', example: 1999.99 })
  @Type(() => Number)
  @IsNumber()
  unitPrice: number;

  @ApiPropertyOptional({ description: 'Compare-at price', example: 2499.99 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  compareAtPrice?: number;

  @ApiPropertyOptional({ description: 'Minimum quantity for tier', example: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  minQuantity?: number;

  @ApiPropertyOptional({
    description: 'Maximum quantity for tier',
    example: 10,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  maxQuantity?: number;

  @ApiPropertyOptional({
    description: 'Valid from date (ISO)',
    example: '2025-01-01T00:00:00Z',
  })
  @IsOptional()
  @IsDateString()
  validFrom?: string;

  @ApiPropertyOptional({
    description: 'Valid to date (ISO)',
    example: '2025-02-01T00:00:00Z',
  })
  @IsOptional()
  @IsDateString()
  validTo?: string;

  @ApiPropertyOptional({
    description: 'Price metadata',
    example: { reason: 'promo' },
  })
  @IsOptional()
  metaJson?: Record<string, unknown>;
}
