import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsInt,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
} from 'class-validator';

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
  @IsInt()
  position?: number;

  @ApiPropertyOptional({ description: 'Weight in grams', example: 200 })
  @IsOptional()
  @IsInt()
  weightGrams?: number;

  @ApiPropertyOptional({ description: 'Height in millimeters', example: 150 })
  @IsOptional()
  @IsInt()
  heightMm?: number;

  @ApiPropertyOptional({ description: 'Width in millimeters', example: 70 })
  @IsOptional()
  @IsInt()
  widthMm?: number;

  @ApiPropertyOptional({ description: 'Depth in millimeters', example: 8 })
  @IsOptional()
  @IsInt()
  depthMm?: number;

  @ApiPropertyOptional({ description: 'Requires shipping', example: true })
  @IsOptional()
  @IsBoolean()
  requiresShipping?: boolean;

  @ApiPropertyOptional({ description: 'Allow backorder if out of stock', example: false })
  @IsOptional()
  @IsBoolean()
  allowBackorder?: boolean;

  @ApiPropertyOptional({ description: 'Arbitrary variant metadata', example: { color: 'black' } })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;
}
