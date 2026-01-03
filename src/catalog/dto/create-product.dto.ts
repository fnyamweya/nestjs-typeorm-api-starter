import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsEnum,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  ValidateNested,
} from 'class-validator';
import { ProductAvailabilityDto } from './product-availability.dto';
import { CreateProductSkuDto } from './create-product-sku.dto';
import { ProductTranslationDto } from './product-translation.dto';
import { CreateProductPriceDto } from './create-product-price.dto';
import { ProductOptionDefinitionDto } from './product-option-definition.dto';

export enum ProductStatus {
  DRAFT = 'draft',
  ACTIVE = 'active',
  ARCHIVED = 'archived',
}

export class CreateProductDto {
  @ApiProperty({ description: 'Product title', example: 'iPhone 15' })
  @IsString()
  @IsNotEmpty()
  title: string;

  @ApiPropertyOptional({ description: 'Product description' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ description: 'Product status', enum: ProductStatus, default: ProductStatus.DRAFT })
  @IsOptional()
  @IsEnum(ProductStatus)
  status?: ProductStatus;

  @ApiPropertyOptional({ description: 'Product slug (auto-generated from title if omitted)' })
  @IsOptional()
  @IsString()
  slug?: string;

  @ApiPropertyOptional({ description: 'External reference', example: 'erp-1234' })
  @IsOptional()
  @IsString()
  externalRef?: string;

  @ApiPropertyOptional({ description: 'Brand id' })
  @IsOptional()
  @IsUUID()
  brandId?: string;

  @ApiPropertyOptional({ description: 'Category ids to attach', isArray: true, type: String })
  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  categoryIds?: string[];

  @ApiPropertyOptional({ description: 'Product option definitions (used to validate SKU options)', type: () => ProductOptionDefinitionDto, isArray: true })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => ProductOptionDefinitionDto)
  optionDefinitions?: ProductOptionDefinitionDto[];

  @ApiPropertyOptional({ description: 'Availability configuration', type: () => ProductAvailabilityDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ProductAvailabilityDto)
  availability?: ProductAvailabilityDto;

  @ApiPropertyOptional({ description: 'Product images', example: ['https://cdn.example.com/img.png'] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  images?: string[];

  @ApiPropertyOptional({ description: 'Translations', type: () => ProductTranslationDto, isArray: true })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => ProductTranslationDto)
  translations?: ProductTranslationDto[];

  @ApiPropertyOptional({ description: 'SKUs', type: () => CreateProductSkuDto, isArray: true })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CreateProductSkuDto)
  skus?: CreateProductSkuDto[];

  @ApiPropertyOptional({ description: 'Product-level prices', type: () => CreateProductPriceDto, isArray: true })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CreateProductPriceDto)
  prices?: CreateProductPriceDto[];

  @ApiPropertyOptional({ description: 'Arbitrary product metadata' })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;
}
