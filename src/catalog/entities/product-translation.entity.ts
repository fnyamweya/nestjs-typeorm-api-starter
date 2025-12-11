import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Product } from './product.entity';

@Entity('product_translation')
@Index('idx_product_translation_locale', ['locale'])
@Index('uq_product_locale', ['productId', 'locale'], { unique: true })
export class ProductTranslation {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'product_id', type: 'uuid' })
  productId: string;

  @ManyToOne(() => Product, (product) => product.translations, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'product_id' })
  product: Product;

  @Column({ type: 'text', nullable: false })
  locale: string;

  @Column({ type: 'text', nullable: false })
  name: string;

  @Column({ name: 'short_description', type: 'text', nullable: true })
  shortDescription?: string;

  @Column({ name: 'long_description', type: 'text', nullable: true })
  longDescription?: string;

  @Column({ name: 'seo_title', type: 'text', nullable: true })
  seoTitle?: string;

  @Column({ name: 'seo_description', type: 'text', nullable: true })
  seoDescription?: string;

  @Column({ name: 'seo_keywords', type: 'text', array: true, nullable: true })
  seoKeywords?: string[];

  @Column({ type: 'text', nullable: true })
  slug?: string;
}
