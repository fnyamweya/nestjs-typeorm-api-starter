import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsArray, IsOptional, IsString, MaxLength } from 'class-validator';

export class ProductTranslationDto {
  @ApiProperty({ description: 'IETF locale code', example: 'en' })
  @IsString()
  locale: string;

  @ApiProperty({ description: 'Localized product name', example: 'iPhone 15' })
  @IsString()
  @MaxLength(255)
  name: string;

  @ApiPropertyOptional({ description: 'Short marketing copy', example: 'Flagship smartphone' })
  @IsOptional()
  @IsString()
  shortDescription?: string;

  @ApiPropertyOptional({ description: 'Long-form description', example: 'Full specs and details' })
  @IsOptional()
  @IsString()
  longDescription?: string;

  @ApiPropertyOptional({ description: 'SEO title for the locale', example: 'Buy iPhone 15 online' })
  @IsOptional()
  @IsString()
  seoTitle?: string;

  @ApiPropertyOptional({ description: 'SEO description', example: 'Shop the latest Apple iPhone 15' })
  @IsOptional()
  @IsString()
  seoDescription?: string;

  @ApiPropertyOptional({ description: 'SEO keyword list', example: ['iphone', 'smartphone'] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  seoKeywords?: string[];

  @ApiPropertyOptional({ description: 'Locale-specific slug override', example: 'iphone-15' })
  @IsOptional()
  @IsString()
  slug?: string;
}
