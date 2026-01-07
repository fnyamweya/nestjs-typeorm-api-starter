import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsBoolean,
  IsDateString,
  IsInt,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  Min,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

class BannerPlacementDto {
  @ApiProperty({
    description:
      'Where the banner should be shown (dynamic key, e.g. landing, category, product)',
    example: 'landing',
  })
  @IsString()
  @IsNotEmpty()
  page: string;

  @ApiPropertyOptional({
    description: 'Section on the page (dynamic, e.g. hero, top, mid, footer)',
    example: 'hero',
  })
  @IsOptional()
  @IsString()
  section?: string;

  @ApiPropertyOptional({
    description: 'Optional ordering position within a section',
    example: 1,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  position?: number;

  // Keep room for additional dynamic placement keys without hardcoding.
  // These will be sent in metaJson if needed.
}

class BannerTargetDto {
  @ApiProperty({
    description:
      'What the banner is associated to (dynamic kind, e.g. taxonomy, category, product, landing)',
    example: 'category',
  })
  @IsString()
  @IsNotEmpty()
  kind: string;

  @ApiPropertyOptional({
    description:
      'Optional reference id (UUID or any external id depending on kind)',
    example: '2d931510-d99f-494a-8c67-87feb05e1594',
  })
  @IsOptional()
  @IsString()
  refId?: string;

  @ApiPropertyOptional({
    description: 'Optional reference code/slug (dynamic)',
    example: 'smartphones',
  })
  @IsOptional()
  @IsString()
  ref?: string;
}

export class CreateBannerDto {
  @ApiProperty({
    description: 'Internal banner name',
    example: 'Homepage Hero Banner',
  })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiPropertyOptional({
    description: 'Whether the banner is active',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({
    description:
      'Banner start time (inclusive). If omitted, banner can start immediately.',
    example: '2026-01-05T00:00:00.000Z',
  })
  @IsOptional()
  @IsDateString()
  startsAt?: string;

  @ApiPropertyOptional({
    description:
      'Banner end time (inclusive). If omitted, banner can run indefinitely.',
    example: '2026-12-31T23:59:59.000Z',
  })
  @IsOptional()
  @IsDateString()
  endsAt?: string;

  @ApiPropertyOptional({
    description:
      'Higher priority banners can be preferred by clients when multiple match.',
    example: 10,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  priority?: number;

  @ApiProperty({
    description:
      "Creative configuration (dynamic). Use kind='image' with imageKey/imageUrl or kind='color' with backgroundColor.",
    example: {
      kind: 'image',
      imageKey: 'banners/home-hero.jpg',
      alt: 'Shop the latest deals',
      cta: { label: 'Shop now', url: '/shop' },
    },
  })
  @IsObject()
  creative: Record<string, unknown>;

  @ApiProperty({
    description:
      'Placements where this banner can appear (dynamic). Client decides how to render each placement.',
    example: [{ page: 'landing', section: 'hero', position: 0 }],
    type: [BannerPlacementDto],
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => BannerPlacementDto)
  placements: BannerPlacementDto[];

  @ApiPropertyOptional({
    description:
      'Targets the banner applies to (dynamic). Example: category/taxonomy/product references.',
    example: [{ kind: 'category', refId: 'uuid-of-category' }],
    type: [BannerTargetDto],
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => BannerTargetDto)
  targets?: BannerTargetDto[];

  @ApiPropertyOptional({
    description:
      'Additional configuration (dynamic). Store any extra banner settings here without schema changes.',
    example: { landingSection: 'topDeals', audience: { channels: ['web'] } },
  })
  @IsOptional()
  @IsObject()
  meta?: Record<string, unknown>;
}
