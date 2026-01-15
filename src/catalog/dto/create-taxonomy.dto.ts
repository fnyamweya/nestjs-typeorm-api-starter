import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
} from 'class-validator';

export class CreateTaxonomyDto {
  @ApiProperty({
    description: 'Machine-readable taxonomy code',
    example: 'product-taxonomy',
  })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({
    description: 'Display name for the taxonomy',
    example: 'Products',
  })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiPropertyOptional({
    description: 'Optional description',
    example: 'Organizes product categories',
  })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({
    description: 'Optional icon',
    example: 'ph:tag',
  })
  @IsOptional()
  @IsString()
  icon?: string;

  @ApiPropertyOptional({
    description: 'Optional avatar image URL',
    example: 'https://cdn.example.com/taxonomy/products.png',
  })
  @IsOptional()
  @IsString()
  avatarUrl?: string;

  @ApiPropertyOptional({
    description: 'Mark as default taxonomy',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  isDefault?: boolean;

  @ApiPropertyOptional({
    description: 'Whether taxonomy is active',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({
    description:
      'Arbitrary metadata JSON blob (supports taxonomy-level shipping rules under metaJson.shipping)',
    example: {
      shipping: { allowedMethodCodes: ['standard'], ratePriorityBoost: 100 },
    },
  })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;
}
