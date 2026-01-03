import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsNotEmpty,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
  ValidateNested,
} from 'class-validator';
import { CreateProductPriceDto } from './create-product-price.dto';

export class CreateProductVariationDto {
  @ApiProperty({ description: 'Variation title', example: 'Black / 128 GB' })
  @IsString()
  @IsNotEmpty()
  title: string;

  @ApiPropertyOptional({ description: 'Stock keeping unit', example: 'IPH-15-BLK-128' })
  @IsOptional()
  @IsString()
  sku?: string;

  @ApiPropertyOptional({ description: 'External reference', example: 'shopify-variant-123' })
  @IsOptional()
  @IsString()
  externalRef?: string;

  @ApiPropertyOptional({ description: 'Variation status', example: 'active' })
  @IsOptional()
  @IsString()
  status?: string;

  @ApiPropertyOptional({ description: 'Mark as default variation', example: true })
  @IsOptional()
  @IsBoolean()
  isDefault?: boolean;

  @ApiPropertyOptional({ description: 'Display order among variations', example: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  position?: number;

  @ApiPropertyOptional({ description: 'Variation attributes', example: { color: 'black', size: 'M' } })
  @IsOptional()
  @IsObject()
  attributes?: Record<string, unknown>;

  @ApiPropertyOptional({ description: 'Variation images', example: ['https://cdn.example.com/1.png'] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  images?: string[];

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

  @ApiPropertyOptional({ description: 'Unit used for dimensions', example: 'cm' })
  @IsOptional()
  @IsString()
  dimensionUnit?: string;

  @ApiPropertyOptional({ description: 'Unit used for weight', example: 'kg' })
  @IsOptional()
  @IsString()
  weightUnit?: string;

  @ApiPropertyOptional({ description: 'Variation metadata', example: { preorder: true } })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;

  @ApiPropertyOptional({ description: 'Variation prices', type: () => CreateProductPriceDto, isArray: true })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CreateProductPriceDto)
  prices?: CreateProductPriceDto[];
}
