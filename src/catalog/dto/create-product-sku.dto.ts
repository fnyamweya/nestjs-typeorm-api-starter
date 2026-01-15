import { ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
  ValidateNested,
} from 'class-validator';
import { CreateProductPriceDto } from './create-product-price.dto';
import { ProductAvailabilityDto } from './product-availability.dto';

export class CreateProductSkuDto {
  @ApiPropertyOptional({ description: 'SKU title', example: 'Black / 128 GB' })
  @IsOptional()
  @IsString()
  title?: string;

  @ApiPropertyOptional({
    description: 'Stock keeping unit',
    example: 'IPH-15-BLK-128',
  })
  @IsOptional()
  @IsString()
  sku?: string;

  @ApiPropertyOptional({
    description: 'External reference',
    example: 'shopify-sku-123',
  })
  @IsOptional()
  @IsString()
  externalRef?: string;

  @ApiPropertyOptional({ description: 'SKU status', example: 'active' })
  @IsOptional()
  @IsString()
  status?: string;

  @ApiPropertyOptional({ description: 'Mark as default SKU', example: true })
  @IsOptional()
  @IsBoolean()
  isDefault?: boolean;

  @ApiPropertyOptional({ description: 'Display order among SKUs', example: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  position?: number;

  @ApiPropertyOptional({
    description: 'SKU attributes',
    example: { color: 'black', size: 'M' },
  })
  @IsOptional()
  @IsObject()
  attributes?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Availability configuration (SKU-level)',
    type: () => ProductAvailabilityDto,
    example: {
      channels: ['WEB', 'APP'],
      countries: ['KE'],
      locations: ['Baringo', 'Dagoretti North'],
      stock: { type: 'FINITE', quantity: 120 },
      schedule: {
        startAt: '2025-01-01T00:00:00Z',
        endAt: '2026-01-01T00:00:00Z',
        timezone: 'UTC',
      },
      meta: { source: 'seed' },
    },
  })
  @IsOptional()
  @ValidateNested()
  @Type(() => ProductAvailabilityDto)
  availability?: ProductAvailabilityDto;

  @ApiPropertyOptional({
    description: 'SKU options (preferred). If both provided, options wins.',
    example: { color: 'black', size: 'M' },
  })
  @IsOptional()
  @IsObject()
  options?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Inventory state by location or warehouse',
    example: { locations: { NAIROBI: { onHand: 10, reserved: 2 } } },
  })
  @IsOptional()
  @IsObject()
  inventory?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'SKU images',
    example: ['https://cdn.example.com/1.png'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  images?: string[];

  @ApiPropertyOptional({ description: 'Requires shipping', example: true })
  @IsOptional()
  @IsBoolean()
  requiresShipping?: boolean;

  @ApiPropertyOptional({
    description: 'Weight with precision support',
    example: 0.2,
  })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  weight?: number;

  @ApiPropertyOptional({
    description: 'Length with precision support',
    example: 10.5,
  })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  length?: number;

  @ApiPropertyOptional({
    description: 'Width with precision support',
    example: 5.25,
  })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  width?: number;

  @ApiPropertyOptional({
    description: 'Height with precision support',
    example: 2.75,
  })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  height?: number;

  @ApiPropertyOptional({
    description: 'Unit used for dimensions',
    example: 'cm',
  })
  @IsOptional()
  @IsString()
  dimensionUnit?: string;

  @ApiPropertyOptional({ description: 'Unit used for weight', example: 'kg' })
  @IsOptional()
  @IsString()
  weightUnit?: string;

  @ApiPropertyOptional({
    description: 'SKU metadata',
    example: { preorder: true },
  })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'SKU prices',
    type: () => CreateProductPriceDto,
    isArray: true,
  })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CreateProductPriceDto)
  prices?: CreateProductPriceDto[];
}
