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

export enum ProductReviewStatus {
  PENDING = 'PENDING',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED',
}

@Entity('product_review')
@Index('uq_product_review_customer_product', ['customerId', 'productId'], {
  unique: true,
})
@Index('idx_product_review_product_status_created', [
  'productId',
  'status',
  'createdAt',
])
export class ProductReview {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'product_id', type: 'uuid' })
  productId: string;

  @Column({ name: 'customer_id', type: 'uuid' })
  customerId: string;

  @Column({ type: 'int' })
  rating: number;

  @Column({ type: 'text', nullable: true })
  title?: string;

  @Column({ type: 'text', nullable: true })
  body?: string;

  @Column({
    name: 'media_urls_json',
    type: 'jsonb',
    default: () => "'[]'::jsonb",
  })
  mediaUrlsJson: string[];

  @Column({ name: 'is_verified_purchase', type: 'boolean', default: false })
  isVerifiedPurchase: boolean;

  @Column({ type: 'text', default: ProductReviewStatus.PENDING })
  status: ProductReviewStatus;

  @Column({ name: 'status_reason', type: 'text', nullable: true })
  statusReason?: string;

  @Column({ name: 'moderated_by_user_id', type: 'uuid', nullable: true })
  moderatedByUserId?: string;

  @Column({ name: 'moderated_at', type: 'timestamptz', nullable: true })
  moderatedAt?: Date;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @ManyToOne(() => Product, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'product_id' })
  product: Product;
}
