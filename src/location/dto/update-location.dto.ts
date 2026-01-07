import { ApiPropertyOptional } from '@nestjs/swagger';
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

export class UpdateLocationDto {
  @ApiPropertyOptional({ description: 'Country ISO2 code', example: 'KE' })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @Length(2, 2)
  countryCode?: string;

  @ApiPropertyOptional({ description: 'Location name' })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  name?: string;

  @ApiPropertyOptional({
    description:
      'Location type (country-configurable). Must match the country locationChain (case-insensitive).',
    example: 'sub_county',
  })
  @IsOptional()
  @Transform(({ value }) => normalizeType(value))
  @IsString()
  @IsNotEmpty()
  type?: string;

  @ApiPropertyOptional({
    description: 'Parent location id (UUID). Set null to make root.',
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
