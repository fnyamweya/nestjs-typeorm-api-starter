import {
  IsOptional,
  IsEnum,
  IsString,
  IsDateString,
  IsBoolean,
} from 'class-validator';
import { ActivityAction } from '../entities/user-activity-log.entity';
import { PaginationFilterDto } from 'src/common/dto/pagination-filter.dto';
import { Transform } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class FilterActivityLogDto extends PaginationFilterDto {
  @ApiPropertyOptional({
    description: 'Filter logs by the associated user ID',
    example: '1ab0c8f0-7d3a-4f5f-80ab-e3f98cd5ef70',
  })
  @IsOptional()
  @IsString()
  userId?: string;

  @ApiPropertyOptional({
    description: 'Filter logs by the type of action performed',
    enum: ActivityAction,
    example: ActivityAction.LOGIN,
  })
  @IsOptional()
  @IsEnum(ActivityAction)
  action?: ActivityAction;

  @ApiPropertyOptional({
    description: 'Restrict to activity log events only when true',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => {
    if (value === undefined || value === null) return undefined;
    if (value === 'true' || value === '1' || value === true) return true;
    if (value === 'false' || value === '0' || value === false) return false;
    return undefined;
  })
  isActivityLog?: boolean;

  @ApiPropertyOptional({
    description: 'Filter logs by resource type (e.g. user, role)',
    example: 'user',
  })
  @IsOptional()
  @IsString()
  resourceType?: string;

  @ApiPropertyOptional({
    description: 'Filter logs by a specific resource identifier',
    example: '42',
  })
  @IsOptional()
  @IsString()
  resourceId?: string;

  @ApiPropertyOptional({
    description: 'Filter logs by IP address recorded',
    example: '203.0.113.10',
  })
  @IsOptional()
  @IsString()
  ipAddress?: string;

  @ApiPropertyOptional({
    description: 'Filter logs by detected device name',
    example: 'MacBook Pro',
  })
  @IsOptional()
  @IsString()
  device?: string;

  @ApiPropertyOptional({
    description: 'Filter logs by detected location string',
    example: 'San Francisco, US',
  })
  @IsOptional()
  @IsString()
  location?: string;

  @ApiPropertyOptional({
    description: 'Filter logs created on or after the provided date',
    example: '2025-01-01T00:00:00.000Z',
    format: 'date-time',
  })
  @IsOptional()
  @IsDateString()
  startDate?: string;

  @ApiPropertyOptional({
    description: 'Filter logs created on or before the provided date',
    example: '2025-01-31T23:59:59.999Z',
    format: 'date-time',
  })
  @IsOptional()
  @IsDateString()
  endDate?: string;

  @ApiPropertyOptional({
    description: 'Field used for sorting results',
    example: 'createdAt',
    default: 'createdAt',
  })
  @IsOptional()
  @IsString()
  sortBy?: string = 'createdAt';

  @ApiPropertyOptional({
    description: 'Sorting order applied to the results',
    example: 'DESC',
    enum: ['ASC', 'DESC'],
    default: 'DESC',
  })
  @IsOptional()
  @IsString()
  sortOrder?: 'ASC' | 'DESC' = 'DESC';
}
