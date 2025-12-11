import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsBoolean,
  IsInt,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  ValidateNested,
} from 'class-validator';
import { CategoryTranslationDto } from './category-translation.dto';

export class CreateCategoryDto {
  @ApiProperty({ description: 'Owning taxonomy id (UUID)', example: '9b1deb4d-5b99-4b8f-9a9b-1b4c2d1f0000' })
  @IsUUID()
  taxonomyId: string;

  @ApiPropertyOptional({ description: 'Optional parent category id (UUID) to build hierarchy' })
  @IsOptional()
  @IsUUID()
  parentId?: string;

  @ApiProperty({ description: 'Stable key for integrations', example: 'phones' })
  @IsString()
  @IsNotEmpty()
  key: string;

  @ApiProperty({ description: 'URL-safe slug', example: 'smartphones' })
  @IsString()
  @IsNotEmpty()
  slug: string;

  @ApiPropertyOptional({ description: 'Whether category is active', example: true })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({ description: 'Mark as leaf node (no children)', example: false })
  @IsOptional()
  @IsBoolean()
  isLeaf?: boolean;

  @ApiPropertyOptional({ description: 'Ordering weight for siblings', example: 5 })
  @IsOptional()
  @IsInt()
  sortOrder?: number;

  @ApiPropertyOptional({ description: 'Optional icon class or URL', example: 'ph:device-mobile' })
  @IsOptional()
  @IsString()
  icon?: string;

  @ApiPropertyOptional({ description: 'Category image URL', example: 'https://cdn.example.com/cat/phones.png' })
  @IsOptional()
  @IsString()
  imageUrl?: string;

  @ApiPropertyOptional({ description: 'Arbitrary metadata JSON blob', example: { theme: 'dark', position: 'hero' } })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Localized content by locale',
    type: () => CategoryTranslationDto,
    isArray: true,
    example: [
      {
        locale: 'en',
        name: 'Smartphones',
        description: 'All mobile phones',
        seoTitle: 'Buy smartphones',
        seoKeywords: ['phones', 'smartphones'],
      },
    ],
  })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CategoryTranslationDto)
  translations?: CategoryTranslationDto[];
}
