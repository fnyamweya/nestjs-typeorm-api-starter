import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsInt, IsOptional, IsString, Min } from 'class-validator';

export class FetchWhatsappProviderTemplatesDto {
  @ApiPropertyOptional({ description: 'Filter by template name' })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({ description: 'Filter by category' })
  @IsOptional()
  @IsString()
  category?: string;

  @ApiPropertyOptional({ description: 'Filter by status' })
  @IsOptional()
  @IsString()
  status?: string;

  @ApiPropertyOptional({
    description: 'Filter by language code',
    example: 'en_US',
  })
  @IsOptional()
  @IsString()
  language?: string;

  @ApiPropertyOptional({
    description: 'Max number of templates to return',
    example: 25,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  limit?: number;

  @ApiPropertyOptional({ description: 'Paging cursor (after)' })
  @IsOptional()
  @IsString()
  after?: string;

  @ApiPropertyOptional({ description: 'Paging cursor (before)' })
  @IsOptional()
  @IsString()
  before?: string;
}
