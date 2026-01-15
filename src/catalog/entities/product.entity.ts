import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ProductOptionDefinition } from './product-option-definition.entity';
import { ProductSku } from './product-sku.entity';
import { JoinColumn, ManyToOne, OneToMany } from 'typeorm';
import { Brand } from './brand.entity';
import { ProductCategory } from './product-category.entity';
import { ProductChannel } from './product-channel.entity';

@Entity('product')
@Index('idx_product_status', ['status', 'createdAt'])
@Index('uq_product_slug', ['slug'], { unique: true })
export class Product {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text', nullable: false })
  title: string;

  @Column({ type: 'text', nullable: true })
  description?: string;

  @Column({ name: 'seo_title', type: 'text', nullable: true })
  seoTitle?: string;

  @Column({ name: 'seo_description', type: 'text', nullable: true })
  seoDescription?: string;

  @Column({ type: 'text', default: 'draft' })
  status: string;

  @Column({ type: 'text', nullable: false })
  slug: string;

  @Column({ name: 'external_ref', type: 'text', nullable: true })
  externalRef?: string;

  @Column({ name: 'brand_id', type: 'uuid', nullable: true })
  brandId?: string;

  @Column({
    name: 'option_definitions_json',
    type: 'jsonb',
    default: () => "'[]'::jsonb",
  })
  optionDefinitionsJson: Array<Record<string, unknown>>;

  // Migration 20260112 introduces metadata_json and backfills from legacy meta_json.
  @Column({
    name: 'metadata_json',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  metaJson: Record<string, unknown>;

  @ManyToOne(() => Brand, (brand) => brand.products, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'brand_id' })
  brand?: Brand;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(() => ProductOptionDefinition, (def) => def.product)
  optionDefinitions: ProductOptionDefinition[];

  @OneToMany(() => ProductSku, (sku) => sku.product)
  skus: ProductSku[];

  @OneToMany(() => ProductChannel, (pc) => pc.product)
  productChannels: ProductChannel[];

  @OneToMany(
    () => ProductCategory,
    (productCategory) => productCategory.product,
  )
  productCategories: ProductCategory[];
}
