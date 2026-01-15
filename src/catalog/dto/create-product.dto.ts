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
import { CreateProductSkuDto } from './create-product-sku.dto';
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

  @ApiPropertyOptional({
    description: 'Product status',
    enum: ProductStatus,
    default: ProductStatus.DRAFT,
  })
  @IsOptional()
  @IsEnum(ProductStatus)
  status?: ProductStatus;

  @ApiPropertyOptional({
    description: 'External reference',
    example: 'erp-1234',
  })
  @IsOptional()
  @IsString()
  externalRef?: string;

  @ApiPropertyOptional({ description: 'SEO title', example: 'Nova X Phone | Shop' })
  @IsOptional()
  @IsString()
  seoTitle?: string;

  @ApiPropertyOptional({
    description: 'SEO description',
    example: 'Flagship smartphone with pro-grade camera and long battery life.',
  })
  @IsOptional()
  @IsString()
  seoDescription?: string;

  @ApiPropertyOptional({ description: 'Brand id' })
  @IsOptional()
  @IsUUID()
  brandId?: string;

  @ApiPropertyOptional({
    description: 'Category ids to attach',
    isArray: true,
    type: String,
  })
  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  categoryIds?: string[];

  @ApiPropertyOptional({
    description: 'Product option definitions (used to validate SKU options)',
    type: () => ProductOptionDefinitionDto,
    isArray: true,
  })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => ProductOptionDefinitionDto)
  optionDefinitions?: ProductOptionDefinitionDto[];

  @ApiPropertyOptional({
    description: 'SKUs',
    type: () => CreateProductSkuDto,
    isArray: true,
  })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CreateProductSkuDto)
  skus?: CreateProductSkuDto[];

  @ApiPropertyOptional({ description: 'Arbitrary product metadata' })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;
}
