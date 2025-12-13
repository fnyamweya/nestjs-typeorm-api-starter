import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsNumber,
  IsDateString,
} from 'class-validator';
import { Type } from 'class-transformer';

export class CreateProductVariantDto {
  @ApiProperty({ description: 'Stock keeping unit', example: 'IPH-15-BLK-128' })
  @IsString()
  @IsNotEmpty()
  sku: string;

  @ApiPropertyOptional({ description: 'Optional barcode', example: '1234567890123' })
  @IsOptional()
  @IsString()
  barcode?: string;

  @ApiPropertyOptional({ description: 'External reference id', example: 'shopify-variant-123' })
  @IsOptional()
  @IsString()
  externalId?: string;

  @ApiProperty({ description: 'Variant title or label', example: 'Black / 128 GB' })
  @IsString()
  @IsNotEmpty()
  title: string;

  @ApiPropertyOptional({ description: 'Mark as default variant', example: true })
  @IsOptional()
  @IsBoolean()
  isDefault?: boolean;

  @ApiPropertyOptional({ description: 'Display order among variants', example: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  position?: number;

  @ApiPropertyOptional({ description: 'Requires shipping', example: true })
  @IsOptional()
  @IsBoolean()
  requiresShipping?: boolean;

  @ApiPropertyOptional({ description: 'Weight with precision support', example: 0.2 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  weight?: number;

  @ApiPropertyOptional({ description: 'Length with precision support', example: 10.5 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  length?: number;

  @ApiPropertyOptional({ description: 'Width with precision support', example: 5.25 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  width?: number;

  @ApiPropertyOptional({ description: 'Height with precision support', example: 2.75 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  height?: number;

  @ApiPropertyOptional({ description: 'Unit used for dimensions', example: 'cm', default: 'cm' })
  @IsOptional()
  @IsString()
  dimensionUnit?: string;

  @ApiPropertyOptional({ description: 'Unit used for weight', example: 'kg', default: 'kg' })
  @IsOptional()
  @IsString()
  weightUnit?: string;

  @ApiPropertyOptional({ description: 'Allow backorder if out of stock', example: false })
  @IsOptional()
  @IsBoolean()
  allowBackorder?: boolean;

  @ApiPropertyOptional({ description: 'Allow preorder before stock arrival', example: true })
  @IsOptional()
  @IsBoolean()
  preorderAvailable?: boolean;

  @ApiPropertyOptional({ description: 'Preorder start date', example: '2024-11-01T00:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  preorderFrom?: string;

  @ApiPropertyOptional({ description: 'Preorder end date', example: '2024-11-15T00:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  preorderTo?: string;

  @ApiPropertyOptional({ description: 'Override tax class for this variant', example: 'reduced' })
  @IsOptional()
  @IsString()
  taxClassOverride?: string;

  @ApiPropertyOptional({ description: 'Override fulfillment class for this variant', example: 'digital' })
  @IsOptional()
  @IsString()
  fulfillmentClassOverride?: string;

  @ApiPropertyOptional({ description: 'Arbitrary variant metadata', example: { color: 'black' } })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;
}
