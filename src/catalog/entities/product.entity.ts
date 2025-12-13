import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  OneToMany,
  OneToOne,
  JoinColumn,
} from 'typeorm';
import { ProductTranslation } from './product-translation.entity';
import { ProductVariant } from './product-variant.entity';
import { ProductOption } from './product-option.entity';
import { ProductCategory } from './product-category.entity';
import { ProductAttributeValue } from './product-attribute-value.entity';

@Entity('product')
@Index('idx_product_status', ['status', 'publishedAt'])
@Index('uq_product_handle', ['handle'], { unique: true })
export class Product {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text', nullable: false })
  handle: string;

  @Column({ type: 'text', default: 'standard' })
  type: string;

  @Column({ type: 'text', default: 'draft' })
  status: string;

  @Column({ name: 'brand_id', type: 'uuid', nullable: true })
  brandId?: string;

  @Column({ name: 'default_variant_id', type: 'uuid', nullable: true })
  defaultVariantId?: string;

  @OneToOne(() => ProductVariant, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'default_variant_id' })
  defaultVariant?: ProductVariant;

  @Column({ name: 'is_featured', type: 'boolean', default: false })
  isFeatured: boolean;

  @Column({ name: 'tax_class_code', type: 'text', nullable: true })
  taxClassCode?: string;

  @Column({ name: 'fulfillment_class', type: 'text', default: 'physical' })
  fulfillmentClass: string;

  @Column({ name: 'country_of_origin', type: 'char', length: 2, nullable: true })
  countryOfOrigin?: string;

  @Column({ name: 'hs_code', type: 'text', nullable: true })
  hsCode?: string;

  @Column({ name: 'inventory_strategy', type: 'text', default: 'variant' })
  inventoryStrategy: string;

  @Column({ name: 'requires_shipping', type: 'boolean', default: true })
  requiresShipping: boolean;

  @Column({ name: 'published_at', type: 'timestamptz', nullable: true })
  publishedAt?: Date;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(() => ProductTranslation, (translation) => translation.product)
  translations: ProductTranslation[];

  @OneToMany(() => ProductVariant, (variant) => variant.product)
  variants: ProductVariant[];

  @OneToMany(() => ProductOption, (option) => option.product)
  options: ProductOption[];

  @OneToMany(() => ProductCategory, (productCategory) => productCategory.product)
  productCategories: ProductCategory[];

  @OneToMany(
    () => ProductAttributeValue,
    (productAttributeValue) => productAttributeValue.product,
  )
  attributeValues: ProductAttributeValue[];
}
