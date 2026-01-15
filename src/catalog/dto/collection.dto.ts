import { ApiProperty, ApiPropertyOptional, PartialType } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { Transform } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsDateString,
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  Min,
  ValidateNested,
} from 'class-validator';
import { CollectionRulePayload, CollectionRuleType } from '../entities/collection.entity';

export class CollectionItemInputDto {
  @ApiProperty({ description: 'Product id to include', example: 'uuid' })
  @IsUUID('4')
  productId: string;

  @ApiPropertyOptional({ description: 'Ordering position', example: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  position?: number;
}

export class CreateCollectionDto {
  @ApiProperty({ description: 'Display title' })
  @IsString()
  @IsNotEmpty()
  title: string;

  @ApiPropertyOptional({ description: 'Description for admins or UI' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({
    description: 'Optional icon',
    example: 'ph:star',
  })
  @IsOptional()
  @IsString()
  icon?: string;

  @ApiPropertyOptional({
    description: 'Optional avatar image URL',
    example: 'https://cdn.example.com/collections/featured.png',
  })
  @IsOptional()
  @IsString()
  avatarUrl?: string;

  @ApiPropertyOptional({ description: 'URL slug (auto-generated from title)' })
  @IsOptional()
  @IsString()
  slug?: string;

  @ApiPropertyOptional({ description: 'Collection type label (free text)', example: 'featured' })
  @IsOptional()
  @IsString()
  type?: string;

  @ApiPropertyOptional({ enum: CollectionRuleType, default: CollectionRuleType.STATIC })
  @IsOptional()
  @IsEnum(CollectionRuleType)
  ruleType?: CollectionRuleType;

  @ApiPropertyOptional({ description: 'Rule payload (for QUERY collections)' })
  @IsOptional()
  @IsObject()
  rulePayload?: CollectionRulePayload;

  @ApiPropertyOptional({ description: 'Whether the collection is active', default: true })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({ description: 'Priority used when ordering collections', default: 0 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  priority?: number;

  @ApiPropertyOptional({ description: 'Start of validity window (ISO 8601)' })
  @IsOptional()
  @IsDateString()
  validFrom?: Date;

  @ApiPropertyOptional({ description: 'End of validity window (ISO 8601)' })
  @IsOptional()
  @IsDateString()
  validTo?: Date;

  @ApiPropertyOptional({
    description: 'Items to include for STATIC collections',
    type: () => CollectionItemInputDto,
    isArray: true,
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CollectionItemInputDto)
  items?: CollectionItemInputDto[];
}

export class UpdateCollectionDto extends PartialType(CreateCollectionDto) {}

export class UpdateCollectionItemsDto {
  @ApiProperty({
    description: 'Ordered items for a static collection (replaces all existing items)',
    type: () => CollectionItemInputDto,
    isArray: true,
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CollectionItemInputDto)
  items: CollectionItemInputDto[];
}

export class FilterCollectionDto {
  @ApiPropertyOptional({ description: 'Collection type label to filter' })
  @IsOptional()
  @IsString()
  type?: string;

  @ApiPropertyOptional({ description: 'Filter by active state' })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({ description: 'Page number', default: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number;

  @ApiPropertyOptional({ description: 'Page size', default: 10 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  limit?: number;
}

export class PublicCollectionsQueryDto {
  @ApiPropertyOptional({ description: 'Comma-separated slugs to fetch' })
  @IsOptional()
  @IsString()
  slugs?: string;

  @ApiPropertyOptional({ description: 'Filter by collection type' })
  @IsOptional()
  @IsString()
  type?: string;

  @ApiPropertyOptional({ description: 'Filter by active state', default: true })
  @IsOptional()
  @Transform(({ value }) => value === 'true' || value === true)
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({
    description: 'How many collections to return when listing',
    default: 20,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  take?: number;

  @ApiPropertyOptional({ description: 'Max items to return per collection', default: 12 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  limit?: number;
}
