import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsNotEmpty, IsObject, IsOptional, IsString, IsUUID, Length } from 'class-validator';
import { LocationType } from '../entities/location.entity';

export class CreateLocationDto {
  @ApiProperty({ description: 'Country ISO2 code', example: 'KE' })
  @IsString()
  @IsNotEmpty()
  @Length(2, 2)
  countryCode: string;

  @ApiProperty({ enum: LocationType, description: 'Location type' })
  @IsEnum(LocationType)
  type: LocationType;

  @ApiProperty({ description: 'Location name', example: 'Nairobi' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiPropertyOptional({ description: 'Parent location id (UUID). Omit to create a root node.' })
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
