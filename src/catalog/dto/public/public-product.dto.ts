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

export class PublicProductVariationDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  title: string;

  @ApiPropertyOptional()
  sku?: string;

  @ApiPropertyOptional({ type: Object })
  attributes?: Record<string, unknown>;

  @ApiPropertyOptional({ type: [String] })
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

export class PublicProductTranslationDto {
  @ApiProperty()
  locale: string;

  @ApiProperty()
  title: string;

  @ApiPropertyOptional()
  description?: string;
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

  @ApiProperty()
  status: string;

  @ApiPropertyOptional()
  externalRef?: string;

  @ApiPropertyOptional({ type: () => PublicBrandDto })
  brand?: PublicBrandDto;

  @ApiProperty({ type: Object })
  availability: Record<string, unknown>;

  @ApiProperty({ type: [String] })
  images: string[];

  @ApiPropertyOptional({ type: () => PublicProductPriceDto })
  price?: PublicProductPriceDto;

  @ApiProperty({ type: () => PublicProductVariationDto, isArray: true })
  variations: PublicProductVariationDto[];

  @ApiProperty({ type: () => PublicProductCategoryRefDto, isArray: true })
  categories: PublicProductCategoryRefDto[];

  @ApiPropertyOptional({ type: () => PublicProductTranslationDto, isArray: true })
  translations?: PublicProductTranslationDto[];
}
