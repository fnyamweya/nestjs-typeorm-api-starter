import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsNotEmpty, IsObject, IsOptional, IsString, IsUUID, Length } from 'class-validator';
import { LocationType } from '../entities/location.entity';

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

  @ApiPropertyOptional({ enum: LocationType, description: 'Location type' })
  @IsOptional()
  @IsEnum(LocationType)
  type?: LocationType;

  @ApiPropertyOptional({ description: 'Parent location id (UUID). Set null to make root.' })
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
