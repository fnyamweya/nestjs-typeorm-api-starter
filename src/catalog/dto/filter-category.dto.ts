import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsOptional, IsUUID } from 'class-validator';

export class FilterCategoryDto {
  @ApiProperty({ description: 'Taxonomy id to scope categories', example: '9b1deb4d-5b99-4b8f-9a9b-1b4c2d1f0000' })
  @IsUUID()
  taxonomyId: string;

  @ApiPropertyOptional({ description: 'Filter by active state', example: true })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}
