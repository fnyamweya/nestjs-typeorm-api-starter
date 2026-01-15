import { ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsInt,
  IsObject,
  IsOptional,
  IsString,
  Min,
  ValidateNested,
} from 'class-validator';

export class ProductAvailabilityStockDto {
  @ApiPropertyOptional({ description: 'Stock type', example: 'FINITE' })
  @IsOptional()
  @IsString()
  type?: string;

  @ApiPropertyOptional({ description: 'Available quantity', example: 20 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  quantity?: number;
}

export class ProductAvailabilityScheduleDto {
  @ApiPropertyOptional({
    description: 'Schedule start (ISO8601)',
    example: '2025-01-01T00:00:00Z',
  })
  @IsOptional()
  @IsString()
  startAt?: string;

  @ApiPropertyOptional({
    description: 'Schedule end (ISO8601)',
    example: '2025-12-31T23:59:59Z',
  })
  @IsOptional()
  @IsString()
  endAt?: string;

  @ApiPropertyOptional({ description: 'Timezone identifier', example: 'UTC' })
  @IsOptional()
  @IsString()
  timezone?: string;
}

export class ProductAvailabilityDto {
  @ApiPropertyOptional({
    description: 'Allowed channels',
    example: ['WEB', 'APP'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  channels?: string[];

  @ApiPropertyOptional({
    description: 'Allowed countries',
    example: ['KE'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  countries?: string[];

  @ApiPropertyOptional({
    description: 'Allowed locations',
    example: ['Baringo', 'Dagoretti North'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  locations?: string[];

  @ApiPropertyOptional({ description: 'Stock configuration' })
  @IsOptional()
  @ValidateNested()
  @Type(() => ProductAvailabilityStockDto)
  stock?: ProductAvailabilityStockDto;

  @ApiPropertyOptional({ description: 'Schedule configuration' })
  @IsOptional()
  @ValidateNested()
  @Type(() => ProductAvailabilityScheduleDto)
  schedule?: ProductAvailabilityScheduleDto;

  @ApiPropertyOptional({ description: 'Additional availability data' })
  @IsOptional()
  @IsObject()
  meta?: Record<string, unknown>;
}
