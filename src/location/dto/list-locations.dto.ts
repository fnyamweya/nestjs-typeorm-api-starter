import { ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsOptional, IsString, IsUUID } from 'class-validator';

function normalizeLocationType(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  return value.toLowerCase();
}

export class ListLocationsDto {
  @ApiPropertyOptional({
    description: 'Parent location id (UUID). Omit for roots.',
    example: '2d1a2b1f-1c9a-4d7b-b44a-9b2a8123c812',
  })
  @IsOptional()
  @IsUUID()
  parentId?: string;

  @ApiPropertyOptional({
    description: 'Country UUID filter (from country_config)',
    example: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
  })
  @IsOptional()
  @IsUUID()
  countryId?: string;

  @ApiPropertyOptional({
    description:
      'Location type filter. This is country-configurable via addresses/field-config.locationChain (case-insensitive).',
    example: 'district',
  })
  @IsOptional()
  @Transform(({ value, obj }) =>
    normalizeLocationType(value ?? obj?.locationType),
  )
  @IsString()
  type?: string;

  @ApiPropertyOptional({
    description:
      'Alias for type (deprecated). Accepts values like COUNTRY, county, sub_county, etc.',
    example: 'COUNTRY',
  })
  @IsOptional()
  @Transform(({ value }) => normalizeLocationType(value))
  @IsString()
  locationType?: string;

  @ApiPropertyOptional({ description: 'Search by name (case-insensitive)' })
  @IsOptional()
  @IsString()
  q?: string;
}
