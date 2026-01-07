import { ApiPropertyOptional } from '@nestjs/swagger';
import { Transform, Type } from 'class-transformer';
import { IsBoolean, IsOptional, IsString } from 'class-validator';
import { PaginationFilterDto } from 'src/common/dto/pagination-filter.dto';

export class FilterBannerDto extends PaginationFilterDto {
  @ApiPropertyOptional({
    description: 'Free text search (matches banner name)',
    example: 'hero',
  })
  @IsOptional()
  @IsString()
  search?: string;

  @ApiPropertyOptional({ description: 'Filter by active flag', example: true })
  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => {
    if (value === undefined || value === null) return undefined;
    if (value === 'true' || value === '1' || value === true) return true;
    if (value === 'false' || value === '0' || value === false) return false;
    return undefined;
  })
  isActive?: boolean;

  @ApiPropertyOptional({
    description: 'Match placements[].page (dynamic)',
    example: 'landing',
  })
  @IsOptional()
  @IsString()
  placementPage?: string;

  @ApiPropertyOptional({
    description: 'Match placements[].section (dynamic)',
    example: 'hero',
  })
  @IsOptional()
  @IsString()
  placementSection?: string;

  @ApiPropertyOptional({
    description: 'Match targets[].kind (dynamic)',
    example: 'category',
  })
  @IsOptional()
  @IsString()
  targetKind?: string;

  @ApiPropertyOptional({
    description: 'Match targets[].refId (dynamic)',
    example: '2d931510-d99f-494a-8c67-87feb05e1594',
  })
  @IsOptional()
  @IsString()
  targetRefId?: string;

  @ApiPropertyOptional({
    description:
      'When true, only return banners valid “right now” (isActive + startsAt/endsAt window). Defaults to false for admin list; public endpoint forces true.',
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
  onlyCurrentlyActive?: boolean;
}
