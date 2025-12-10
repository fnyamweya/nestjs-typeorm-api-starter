import { IsOptional, IsNumber, Min, IsBoolean } from 'class-validator';
import { Transform, Type } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class PaginationFilterDto {
  @ApiPropertyOptional({
    description: 'Page number for paginated results (1-based index)',
    example: 1,
    minimum: 1,
  })
  @IsOptional()
  @IsNumber({}, { message: 'Page must be a number' })
  @Min(1, { message: 'Page must be at least 1' })
  @Type(() => Number)
  page: number = 1;

  @ApiPropertyOptional({
    description: 'Maximum number of items returned per page',
    example: 10,
    minimum: 1,
  })
  @IsOptional()
  @IsNumber({}, { message: 'Limit must be a number' })
  @Min(1, { message: 'Limit must be at least 1' })
  @Type(() => Number)
  limit: number = 10;

  @ApiPropertyOptional({
    description: 'When true the request returns all records without pagination',
    example: false,
  })
  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => {
    if (value === undefined || value === null) return undefined;
    if (value === 'true' || value === '1' || value === true) return true;
    if (value === 'false' || value === '0' || value === false) return false;
    return undefined;
  })
  getAll: boolean = false;
}
