import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString, IsUUID, Length } from 'class-validator';
import { LocationType } from '../entities/location.entity';

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

  @ApiPropertyOptional({ description: 'Location type filter', enum: Object.values(LocationType) })
  @IsOptional()
  @IsIn(Object.values(LocationType))
  type?: LocationType;

  @ApiPropertyOptional({ description: 'Search by name (case-insensitive)' })
  @IsOptional()
  @IsString()
  q?: string;
}
