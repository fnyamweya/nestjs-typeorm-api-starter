import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
} from 'class-validator';

function normalizeType(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  return value.toLowerCase();
}

export class CreateLocationDto {
  @ApiProperty({
    description: 'Country UUID (from country_config)',
    example: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
  })
  @IsUUID()
  countryId: string;

  @ApiProperty({
    description:
      'Location type (country-configurable). Must match the country locationChain (case-insensitive).',
    example: 'county',
  })
  @Transform(({ value }) => normalizeType(value))
  @IsString()
  @IsNotEmpty()
  type: string;

  @ApiProperty({ description: 'Location name', example: 'Nairobi' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiPropertyOptional({
    description: 'Parent location id (UUID). Omit to create a root node.',
    example: '2d1a2b1f-1c9a-4d7b-b44a-9b2a8123c812',
  })
  @IsOptional()
  @IsUUID()
  parentId?: string;

  @ApiPropertyOptional({ description: 'Optional stable code' })
  @IsOptional()
  @IsString()
  code?: string;

  @ApiPropertyOptional({ description: 'Optional metadata JSON' })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;
}
