import {
  Column,
  Entity,
  Index,
  JoinColumn,
  OneToOne,
  PrimaryColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Product } from './product.entity';

@Entity('product_rating_summary')
@Index('idx_product_rating_summary_updated', ['updatedAt'])
export class ProductRatingSummary {
  @PrimaryColumn({ name: 'product_id', type: 'uuid' })
  productId: string;

  @Column({ name: 'rating_count', type: 'int', default: 0 })
  ratingCount: number;

  @Column({ name: 'avg_rating', type: 'numeric', precision: 10, scale: 4, default: 0 })
  avgRating: string;

  @Column({ name: 'star_1_count', type: 'int', default: 0 })
  star1Count: number;

  @Column({ name: 'star_2_count', type: 'int', default: 0 })
  star2Count: number;

  @Column({ name: 'star_3_count', type: 'int', default: 0 })
  star3Count: number;

  @Column({ name: 'star_4_count', type: 'int', default: 0 })
  star4Count: number;

  @Column({ name: 'star_5_count', type: 'int', default: 0 })
  star5Count: number;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToOne(() => Product, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'product_id' })
  product: Product;
}
