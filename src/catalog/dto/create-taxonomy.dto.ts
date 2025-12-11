import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateTaxonomyDto {
  @ApiProperty({ description: 'Machine-readable taxonomy code', example: 'product-taxonomy' })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({ description: 'Display name for the taxonomy', example: 'Products' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiPropertyOptional({ description: 'Optional description', example: 'Organizes product categories' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ description: 'Mark as default taxonomy', example: true })
  @IsOptional()
  @IsBoolean()
  isDefault?: boolean;
}
