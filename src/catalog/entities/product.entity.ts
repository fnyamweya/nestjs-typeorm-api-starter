import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Brand } from './brand.entity';
import { ProductCategory } from './product-category.entity';
import { ProductChannel } from './product-channel.entity';
import { ProductPrice } from './product-price.entity';
import { ProductTranslation } from './product-translation.entity';
import { ProductVariant } from './product-variant.entity';

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

  @Column({ type: 'text', default: 'draft' })
  status: string;

  @Column({ type: 'text', nullable: false })
  slug: string;

  @Column({ name: 'external_ref', type: 'text', nullable: true })
  externalRef?: string;

  @Column({ name: 'brand_id', type: 'uuid', nullable: true })
  brandId?: string;

  @ManyToOne(() => Brand, (brand) => brand.products, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'brand_id' })
  brand?: Brand;

  @Column({ name: 'availability_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  availabilityJson: Record<string, unknown>;

  @Column({ name: 'images_json', type: 'jsonb', default: () => "'[]'::jsonb" })
  imagesJson: string[];

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

  @OneToMany(() => ProductCategory, (productCategory) => productCategory.product)
  productCategories: ProductCategory[];

  @OneToMany(() => ProductChannel, (productChannel) => productChannel.product)
  productChannels: ProductChannel[];

  @OneToMany(() => ProductPrice, (price) => price.product)
  prices: ProductPrice[];
}
