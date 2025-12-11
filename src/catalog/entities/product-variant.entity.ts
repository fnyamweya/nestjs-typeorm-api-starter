import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  OneToMany,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Product } from './product.entity';
import { VariantOptionValue } from './variant-option-value.entity';

@Entity('product_variant')
@Index('idx_variant_product', ['productId', 'isDefault'])
@Index('uq_variant_sku', ['sku'], { unique: true })
export class ProductVariant {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'product_id', type: 'uuid' })
  productId: string;

  @ManyToOne(() => Product, (product) => product.variants, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'product_id' })
  product: Product;

  @Column({ type: 'text', nullable: false })
  sku: string;

  @Column({ type: 'text', nullable: true })
  barcode?: string;

  @Column({ name: 'external_id', type: 'text', nullable: true })
  externalId?: string;

  @Column({ type: 'text', nullable: false })
  title: string;

  @Column({ name: 'is_default', type: 'boolean', default: false })
  isDefault: boolean;

  @Column({ type: 'int', default: 0 })
  position: number;

  @Column({ name: 'weight_grams', type: 'int', nullable: true })
  weightGrams?: number;

  @Column({ name: 'height_mm', type: 'int', nullable: true })
  heightMm?: number;

  @Column({ name: 'width_mm', type: 'int', nullable: true })
  widthMm?: number;

  @Column({ name: 'depth_mm', type: 'int', nullable: true })
  depthMm?: number;

  @Column({ name: 'requires_shipping', type: 'boolean', default: true })
  requiresShipping: boolean;

  @Column({ name: 'allow_backorder', type: 'boolean', default: false })
  allowBackorder: boolean;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(
    () => VariantOptionValue,
    (variantOptionValue: VariantOptionValue) => variantOptionValue.variant,
  )
  optionValues: VariantOptionValue[];
}
