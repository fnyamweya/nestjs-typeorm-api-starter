import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsDateString,
  IsEnum,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  ValidateNested,
} from 'class-validator';
import { CreateProductVariantDto } from './create-product-variant.dto';
import { ProductTranslationDto } from './product-translation.dto';

enum ProductType {
  STANDARD = 'standard',
  BUNDLE = 'bundle',
  VIRTUAL = 'virtual',
}

enum ProductStatus {
  DRAFT = 'draft',
  ACTIVE = 'active',
  ARCHIVED = 'archived',
}

export class CreateProductDto {
  @ApiProperty({ description: 'Unique product handle', example: 'iphone-15' })
  @IsString()
  @IsNotEmpty()
  handle: string;

  @ApiPropertyOptional({ description: 'Product type', enum: ProductType, default: ProductType.STANDARD })
  @IsOptional()
  @IsEnum(ProductType)
  type?: ProductType;

  @ApiPropertyOptional({ description: 'Product lifecycle status', enum: ProductStatus, default: ProductStatus.DRAFT })
  @IsOptional()
  @IsEnum(ProductStatus)
  status?: ProductStatus;

  @ApiPropertyOptional({ description: 'Optional brand id', example: 'a3f1c6e9-1c63-4a9c-8b3f-5b2f4c57b000' })
  @IsOptional()
  @IsUUID()
  brandId?: string;

  @ApiPropertyOptional({ description: 'Feature for merchandising', example: false })
  @IsOptional()
  @IsBoolean()
  isFeatured?: boolean;

  @ApiPropertyOptional({ description: 'Publishing date', example: '2024-01-15T10:00:00.000Z' })
  @IsOptional()
  @IsDateString()
  publishedAt?: string;

  @ApiPropertyOptional({ description: 'Arbitrary product metadata', example: { season: 'SS24' } })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Localized content per locale',
    type: () => ProductTranslationDto,
    isArray: true,
    example: [
      { locale: 'en', name: 'iPhone 15', shortDescription: 'Flagship phone' },
      { locale: 'fr', name: 'iPhone 15', shortDescription: 'Smartphone phare' },
    ],
  })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => ProductTranslationDto)
  translations?: ProductTranslationDto[];

  @ApiPropertyOptional({
    description: 'Variants payload',
    type: () => CreateProductVariantDto,
    isArray: true,
    example: [
      {
        sku: 'IPH-15-BLK-128',
        title: 'Black / 128 GB',
        isDefault: true,
      },
    ],
  })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CreateProductVariantDto)
  variants?: CreateProductVariantDto[];

  @ApiPropertyOptional({ description: 'Category ids to attach', isArray: true, type: String })
  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  categoryIds?: string[];
}

export { ProductType, ProductStatus };
