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
import { PriceList } from './price-list.entity';
import { Product } from './product.entity';
import { ProductVariant } from './product-variant.entity';

@Entity('product_price')
@Index('idx_product_price_lookup', ['priceListId', 'productId', 'productVariantId'])
export class ProductPrice {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'price_list_id', type: 'uuid' })
  priceListId: string;

  @ManyToOne(() => PriceList, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'price_list_id' })
  priceList: PriceList;

  @Column({ name: 'product_id', type: 'uuid' })
  productId: string;

  @ManyToOne(() => Product, (product) => product.prices, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'product_id' })
  product: Product;

  @Column({ name: 'product_variant_id', type: 'uuid', nullable: true })
  productVariantId?: string;

  @ManyToOne(() => ProductVariant, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'product_variant_id' })
  productVariant?: ProductVariant;

  @Column({ name: 'unit_price', type: 'numeric', precision: 18, scale: 4 })
  unitPrice: string;

  @Column({ name: 'compare_at_price', type: 'numeric', precision: 18, scale: 4, nullable: true })
  compareAtPrice?: string;

  @Column({ name: 'min_quantity', type: 'int', default: 1 })
  minQuantity: number;

  @Column({ name: 'max_quantity', type: 'int', nullable: true })
  maxQuantity?: number;

  @Column({ name: 'valid_from', type: 'timestamptz', nullable: true })
  validFrom?: Date;

  @Column({ name: 'valid_to', type: 'timestamptz', nullable: true })
  validTo?: Date;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
