import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Product } from './product.entity';

export type SkuStatus = 'active' | 'inactive' | 'archived';

@Entity('product_sku')
@Index('uq_product_sku_sku', ['sku'], { unique: true })
@Index('idx_product_sku_product', ['productId', 'isDefault'])
export class ProductSku {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'product_id', type: 'uuid' })
  productId: string;

  @ManyToOne(() => Product, (product) => product.skus, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'product_id' })
  product: Product;

  @Column({ type: 'text' })
  sku: string;

  @Column({ type: 'text' })
  title: string;

  @Column({ name: 'external_ref', type: 'text', nullable: true })
  externalRef?: string;

  @Column({ type: 'text', default: 'active' })
  status: SkuStatus;

  @Column({ name: 'is_default', type: 'boolean', default: false })
  isDefault: boolean;

  @Column({ type: 'int', default: 0 })
  position: number;

  @Column({ name: 'options_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  options: Record<string, string>;

  @Column({
    name: 'attributes_json',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  attributes: Record<string, unknown>;

  @Column({ name: 'requires_shipping', type: 'boolean', default: true })
  requiresShipping: boolean;

  // Inventory stored as structured json (validated at API layer)
  @Column({
    name: 'inventory_json',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  inventory: Record<string, unknown>;

  @Column({ name: 'images_json', type: 'jsonb', default: () => "'[]'::jsonb" })
  imagesJson: string[];

  @Column({
    name: 'availability',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  availability: Record<string, unknown>;

  @Column({
    name: 'weight',
    type: 'numeric',
    precision: 18,
    scale: 6,
    nullable: true,
  })
  weight?: string;

  @Column({
    name: 'length',
    type: 'numeric',
    precision: 18,
    scale: 6,
    nullable: true,
  })
  length?: string;

  @Column({
    name: 'width',
    type: 'numeric',
    precision: 18,
    scale: 6,
    nullable: true,
  })
  width?: string;

  @Column({
    name: 'height',
    type: 'numeric',
    precision: 18,
    scale: 6,
    nullable: true,
  })
  height?: string;

  @Column({ name: 'dimension_unit', type: 'text', default: 'cm' })
  dimensionUnit: string;

  @Column({ name: 'weight_unit', type: 'text', default: 'kg' })
  weightUnit: string;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
