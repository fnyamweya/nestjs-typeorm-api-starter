import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsArray,
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

export class CategoryShippingMatrixItemDto {
  @ApiProperty({ example: 'Nairobi & Kiambu' })
  @IsString()
  @IsNotEmpty()
  region: string;

  @ApiProperty({ example: 'Same/next day' })
  @IsString()
  @IsNotEmpty()
  sla: string;

  @ApiProperty({ example: 'KES 0' })
  @IsString()
  @IsNotEmpty()
  surcharge: string;
}

export class CreateCategoryDto {
  @ApiProperty({
    description: 'Owning taxonomy id (UUID)',
    example: '9b1deb4d-5b99-4b8f-9a9b-1b4c2d1f0000',
  })
  @IsUUID()
  taxonomyId: string;

  @ApiPropertyOptional({
    description: 'Optional parent category id (UUID) to build hierarchy',
  })
  @IsOptional()
  @IsUUID()
  parentId?: string;

  @ApiPropertyOptional({
    description:
      "Parent category id (UUID) or 'ROOT' to create a root category (admin UI)",
    example: 'ROOT',
  })
  @IsOptional()
  @IsString()
  parent?: string;

  @ApiPropertyOptional({
    description:
      'Stable key for integrations (defaults to the slug when omitted)',
    example: 'phones',
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  key?: string;

  @ApiPropertyOptional({
    description:
      'Category display name (used to auto-generate slug if omitted)',
    example: 'Smartphones',
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  name?: string;

  @ApiPropertyOptional({
    description: 'URL-safe slug (auto-generated from name/key if omitted)',
    example: 'smartphones',
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  slug?: string;

  @ApiPropertyOptional({
    description: 'Whether category is active',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({
    description: "Status ('active'|'inactive') (admin UI)",
    example: 'active',
  })
  @IsOptional()
  @IsString()
  status?: string;

  @ApiPropertyOptional({
    description: 'Mark as leaf node (no children)',
    example: false,
  })
  @IsOptional()
  @IsBoolean()
  isLeaf?: boolean;

  @ApiPropertyOptional({
    description: 'Ordering weight for siblings',
    example: 5,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  sortOrder?: number;

  @ApiPropertyOptional({
    description: 'Order/position (alias for sortOrder) (admin UI)',
    example: 1,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  order?: number;

  @ApiPropertyOptional({
    description: 'Optional icon class or URL',
    example: 'ph:device-mobile',
  })
  @IsOptional()
  @IsString()
  icon?: string;

  @ApiPropertyOptional({
    description: 'Optional avatar image URL',
    example: 'https://cdn.example.com/cat/phones-avatar.png',
  })
  @IsOptional()
  @IsString()
  avatarUrl?: string;

  @ApiPropertyOptional({
    description: 'Category image URL',
    example: 'https://cdn.example.com/cat/phones.png',
  })
  @IsOptional()
  @IsString()
  imageUrl?: string;

  @ApiPropertyOptional({ description: 'Category description (admin UI)' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ description: 'SEO title (admin UI)' })
  @IsOptional()
  @IsString()
  seoTitle?: string;

  @ApiPropertyOptional({ description: 'SEO description (admin UI)' })
  @IsOptional()
  @IsString()
  seoDescription?: string;

  @ApiPropertyOptional({
    description: 'Synonyms (comma-separated) (admin UI)',
    example: 'phones,mobiles,handsets',
  })
  @IsOptional()
  @IsString()
  synonyms?: string;

  @ApiPropertyOptional({
    description: 'Keywords (comma-separated) (admin UI)',
    example: 'phones,smartphones,android',
  })
  @IsOptional()
  @IsString()
  keywords?: string;

  @ApiPropertyOptional({ description: 'Level (admin UI)', example: 'primary' })
  @IsOptional()
  @IsString()
  level?: string;

  @ApiPropertyOptional({ description: 'Audience (admin UI)', example: 'all' })
  @IsOptional()
  @IsString()
  audience?: string;

  @ApiPropertyOptional({
    description: 'Return policy code (admin UI)',
    example: 'standard',
  })
  @IsOptional()
  @IsString()
  returnPolicy?: string;

  @ApiPropertyOptional({
    description: 'Tax code (admin UI)',
    example: 'GEN-001',
  })
  @IsOptional()
  @IsString()
  taxCode?: string;

  @ApiPropertyOptional({
    description: 'Highlight category (admin UI)',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  highlight?: boolean;

  @ApiPropertyOptional({
    description: 'Show in navigation (admin UI)',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  navPlacement?: boolean;

  @ApiPropertyOptional({
    description: 'Featured category (admin UI)',
    example: false,
  })
  @IsOptional()
  @IsBoolean()
  featured?: boolean;

  @ApiPropertyOptional({ description: 'Banner URL or identifier (admin UI)' })
  @IsOptional()
  @IsString()
  banner?: string;

  @ApiPropertyOptional({ description: 'Margin target (admin UI)', example: 18 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  marginTarget?: number;

  @ApiPropertyOptional({
    description: 'Availability (admin UI)',
    example: 'global',
  })
  @IsOptional()
  @IsString()
  availability?: string;

  @ApiPropertyOptional({ description: 'Compliance info (admin UI)' })
  @IsOptional()
  @IsString()
  compliance?: string;

  @ApiPropertyOptional({
    description: 'Shipping profile code (admin UI)',
    example: 'standard',
  })
  @IsOptional()
  @IsString()
  shippingProfile?: string;

  @ApiPropertyOptional({ description: 'Marketing headline (admin UI)' })
  @IsOptional()
  @IsString()
  marketingHeadline?: string;

  @ApiPropertyOptional({ description: 'Marketing sub headline (admin UI)' })
  @IsOptional()
  @IsString()
  marketingSub?: string;

  @ApiPropertyOptional({ description: 'Hero CTA text (admin UI)' })
  @IsOptional()
  @IsString()
  heroCta?: string;

  @ApiPropertyOptional({ description: 'Hero CTA link (admin UI)' })
  @IsOptional()
  @IsString()
  heroCtaLink?: string;

  @ApiPropertyOptional({ description: 'Content pillar (admin UI)' })
  @IsOptional()
  @IsString()
  contentPillar?: string;

  @ApiPropertyOptional({ description: 'Story/content (admin UI)' })
  @IsOptional()
  @IsString()
  story?: string;

  @ApiPropertyOptional({
    description: 'Theme color (admin UI)',
    example: '#f97316',
  })
  @IsOptional()
  @IsString()
  themeColor?: string;

  @ApiPropertyOptional({
    description: 'Shipping matrix rows (admin UI)',
    type: () => CategoryShippingMatrixItemDto,
    isArray: true,
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CategoryShippingMatrixItemDto)
  shippingMatrix?: CategoryShippingMatrixItemDto[];

  @ApiPropertyOptional({
    description: 'Arbitrary metadata JSON blob (merged with UI fields)',
    example: { theme: 'dark', position: 'hero' },
  })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Localized content by locale',
    type: () => CategoryTranslationDto,
    isArray: true,
  })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CategoryTranslationDto)
  translations?: CategoryTranslationDto[];
}
