import { ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsOptional, IsString, IsUUID, Length } from 'class-validator';

function normalizeLocationType(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  return value.toLowerCase();
}

export class ListLocationsDto {
  @ApiPropertyOptional({ description: 'Parent location id (UUID). Omit for roots.' })
  @IsOptional()
  @IsUUID()
  parentId?: string;

  @ApiPropertyOptional({ description: 'Country ISO2 code filter', example: 'KE' })
  @IsOptional()
  @IsString()
  @Length(2, 2)
  countryCode?: string;

  @ApiPropertyOptional({
    description:
      'Location type filter. This is country-configurable via addresses/field-config.locationChain (case-insensitive).',
    example: 'district',
  })
  @IsOptional()
  @Transform(({ value, obj }) => normalizeLocationType(value ?? obj?.locationType))
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
