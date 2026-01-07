import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  Length,
} from 'class-validator';

function normalizeType(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  return value.toLowerCase();
}

export class CreateLocationDto {
  @ApiProperty({ description: 'Country ISO2 code', example: 'KE' })
  @IsString()
  @IsNotEmpty()
  @Length(2, 2)
  countryCode: string;

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
