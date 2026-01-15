import {
  AppliedOverrideInfo,
  AttributeValue,
  ContextualOverrideDTO,
  ID,
  LocalizedString,
  LocalizedText,
  ProductStatus,
  ProductType,
} from './product.types';
import { PublicBrandDto } from '../public/public-brand.dto';
import { PublicCategoryDto } from '../public/public-category.dto';

export interface ProductDTO {
  // --------------------------------------------------
  // 1. Core Identity
  // --------------------------------------------------
  id: string;
  code: string;
  slug?: string;
  type: ProductType;

  // --------------------------------------------------
  // 2. Classification & Taxonomy
  // --------------------------------------------------
  categories: PublicCategoryDto[];
  tags?: string[];
  collections?: string[];
  brand?: PublicBrandDto;

  // --------------------------------------------------
  // 3. Human-Facing Metadata
  // --------------------------------------------------
  name: LocalizedString;
  description?: LocalizedString;

  // --------------------------------------------------
  // 4. Dynamic Attributes (Schema-Driven)
  // --------------------------------------------------
  attributes: Record<string, AttributeValue>;
  attributeSchemaRef: {
    schemaId: string;
    schemaVersion: number;
  };

  // --------------------------------------------------
  // 5. Commercial Model
  // --------------------------------------------------
  taxation?: Record<string, unknown>;
  discounts?: Array<Record<string, unknown>>;

  // --------------------------------------------------
  // 6. Availability & Lifecycle
  // --------------------------------------------------
  status: ProductStatus;

  // --------------------------------------------------
  // 9. Contextual Overrides
  // --------------------------------------------------
  overrides?: ContextualOverrideDTO[];

  skus?: Array<{
    id: ID;
    code: string;
    name?: LocalizedText;
    attributes?: Record<string, unknown>;
  }>;
}

export interface ProductViewDTO extends ProductDTO {
  appliedOverrides: AppliedOverrideInfo[];
}
