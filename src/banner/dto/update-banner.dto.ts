import { ApiPropertyOptional } from '@nestjs/swagger';
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
  @ApiPropertyOptional({
    description: 'Where the banner should be shown (dynamic key)',
    example: 'landing',
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  page?: string;

  @ApiPropertyOptional({
    description: 'Section on the page (dynamic)',
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
}

class BannerTargetDto {
  @ApiPropertyOptional({
    description: 'Dynamic target kind',
    example: 'category',
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  kind?: string;

  @ApiPropertyOptional({
    description: 'Optional reference id',
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

export class UpdateBannerDto {
  @ApiPropertyOptional({
    description: 'Internal banner name',
    example: 'Homepage Hero Banner',
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  name?: string;

  @ApiPropertyOptional({
    description: 'Whether the banner is active',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({
    description: 'Banner start time (inclusive)',
    example: '2026-01-05T00:00:00.000Z',
  })
  @IsOptional()
  @IsDateString()
  startsAt?: string;

  @ApiPropertyOptional({
    description: 'Banner end time (inclusive)',
    example: '2026-12-31T23:59:59.000Z',
  })
  @IsOptional()
  @IsDateString()
  endsAt?: string;

  @ApiPropertyOptional({ description: 'Priority', example: 10 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  priority?: number;

  @ApiPropertyOptional({
    description:
      "Creative configuration (dynamic). Use kind='image' with imageKey/imageUrl or kind='color' with backgroundColor.",
    example: {
      kind: 'color',
      backgroundColor: '#FF0000',
      textColor: '#FFFFFF',
    },
  })
  @IsOptional()
  @IsObject()
  creative?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Replace placements array (dynamic).',
    example: [{ page: 'landing', section: 'hero', position: 0 }],
    type: [BannerPlacementDto],
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => BannerPlacementDto)
  placements?: BannerPlacementDto[];

  @ApiPropertyOptional({
    description: 'Replace targets array (dynamic).',
    example: [{ kind: 'product', refId: 'uuid-of-product' }],
    type: [BannerTargetDto],
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => BannerTargetDto)
  targets?: BannerTargetDto[];

  @ApiPropertyOptional({
    description: 'Merge/replace extra configuration',
    example: { landingSection: 'topDeals' },
  })
  @IsOptional()
  @IsObject()
  meta?: Record<string, unknown>;
}
