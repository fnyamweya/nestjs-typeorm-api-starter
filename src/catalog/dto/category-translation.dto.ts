import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsArray, IsOptional, IsString, MaxLength, ValidateNested } from 'class-validator';

export class CategoryTranslationDto {
  @ApiProperty({ description: 'IETF locale code', example: 'en' })
  @IsString()
  locale: string;

  @ApiProperty({ description: 'Localized category name', example: 'Smartphones' })
  @IsString()
  @MaxLength(255)
  name: string;

  @ApiPropertyOptional({ description: 'Localized description', example: 'All mobile phone categories' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ description: 'SEO title for the locale', example: 'Shop smartphones' })
  @IsOptional()
  @IsString()
  seoTitle?: string;

  @ApiPropertyOptional({ description: 'SEO description', example: 'Discover mobile phones and accessories' })
  @IsOptional()
  @IsString()
  seoDescription?: string;

  @ApiPropertyOptional({ description: 'SEO keyword list', example: ['phones', 'smartphones'] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  seoKeywords?: string[];

  @ApiPropertyOptional({ description: 'Optional URL path override', example: '/electronics/phones' })
  @IsOptional()
  @IsString()
  urlPath?: string;
}

export class CategoryTranslationArrayDto {
  @ApiProperty({
    description: 'Localized translations payload',
    type: () => CategoryTranslationDto,
    isArray: true,
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CategoryTranslationDto)
  translations: CategoryTranslationDto[];
}
