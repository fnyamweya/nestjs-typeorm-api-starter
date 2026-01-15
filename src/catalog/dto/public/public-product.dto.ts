import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { PublicBrandDto } from './public-brand.dto';

export class PublicProductPriceDto {
  @ApiProperty()
  priceListId: string;

  @ApiProperty()
  currencyCode: string;

  @ApiProperty()
  unitPrice: string;

  @ApiPropertyOptional()
  compareAtPrice?: string;
}

export class PublicProductSkuDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  title: string;

  @ApiPropertyOptional()
  sku?: string;

  @ApiPropertyOptional({ type: Object })
  attributes?: Record<string, unknown>;

  @ApiPropertyOptional({ type: Object })
  @ApiPropertyOptional({
    type: Object,
    example: {
      channels: ['WEB', 'APP'],
      countries: ['KE'],
      locations: ['Baringo', 'Dagoretti North'],
      stock: { type: 'FINITE', quantity: 120 },
      schedule: {
        startAt: '2025-01-01T00:00:00Z',
        endAt: '2026-01-01T00:00:00Z',
        timezone: 'UTC',
      },
    },
  })
  availability?: Record<string, unknown>;

  @ApiPropertyOptional({
    type: [String],
    example: ['https://cdn.example.com/products/nova-x/black.png'],
  })
  images?: string[];

  @ApiPropertyOptional({ type: () => PublicProductPriceDto })
  price?: PublicProductPriceDto;
}

export class PublicProductCategoryRefDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  taxonomyId: string;

  @ApiPropertyOptional()
  parentId?: string;

  @ApiProperty()
  key: string;

  @ApiProperty()
  slug: string;

  @ApiProperty()
  name: string;
}

export class PublicProductDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  slug: string;

  @ApiProperty()
  title: string;

  @ApiPropertyOptional()
  description?: string;

  @ApiPropertyOptional({ example: 'Nova X Phone | Shop' })
  seoTitle?: string;

  @ApiPropertyOptional({
    example: 'Flagship smartphone with pro-grade camera and long battery life.',
  })
  seoDescription?: string;

  @ApiProperty()
  status: string;

  @ApiPropertyOptional()
  externalRef?: string;

  @ApiPropertyOptional({ type: () => PublicBrandDto })
  brand?: PublicBrandDto;

  @ApiProperty({ type: () => PublicProductSkuDto, isArray: true })
  skus: PublicProductSkuDto[];

  @ApiProperty({ type: () => PublicProductCategoryRefDto, isArray: true })
  categories: PublicProductCategoryRefDto[];
}
