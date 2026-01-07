import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsInt, IsOptional, IsString, IsUUID, Min } from 'class-validator';

export class PublicListProductsDto {
  @ApiPropertyOptional({ description: 'Page number (default 1)', example: 1 })
  @IsOptional()
  @IsInt()
  @Min(1)
  page?: number;

  @ApiPropertyOptional({ description: 'Page size (default 10)', example: 10 })
  @IsOptional()
  @IsInt()
  @Min(1)
  limit?: number;

  @ApiPropertyOptional({
    description: 'Search term applied to title/slug',
    example: 'iphone',
  })
  @IsOptional()
  @IsString()
  search?: string;

  @ApiPropertyOptional({ description: 'Filter by brand id' })
  @IsOptional()
  @IsUUID('4')
  brandId?: string;

  @ApiPropertyOptional({ description: 'Filter by category id' })
  @IsOptional()
  @IsUUID('4')
  categoryId?: string;

  @ApiPropertyOptional({
    description: 'Filter by taxonomy id (via product categories)',
  })
  @IsOptional()
  @IsUUID('4')
  taxonomyId?: string;

  @ApiPropertyOptional({
    description: 'Channel code for availability filter',
    example: 'app',
  })
  @IsOptional()
  @IsString()
  channel?: string;

  @ApiPropertyOptional({
    description: 'Country code for availability filter',
    example: 'KE',
  })
  @IsOptional()
  @IsString()
  country?: string;

  @ApiPropertyOptional({ description: 'Location filter', example: 'Nairobi' })
  @IsOptional()
  @IsString()
  location?: string;

  @ApiPropertyOptional({
    description: 'Preferred locale for translated fields',
    example: 'en',
  })
  @IsOptional()
  @IsString()
  locale?: string;

  @ApiPropertyOptional({ description: 'Price list id for price resolution' })
  @IsOptional()
  @IsUUID('4')
  priceListId?: string;

  @ApiPropertyOptional({
    description: 'Currency code for price resolution',
    example: 'KES',
  })
  @IsOptional()
  @IsString()
  currencyCode?: string;
}
