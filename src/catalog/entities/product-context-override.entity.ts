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

@Entity('product_context_override')
@Index('idx_product_context_override_product', ['productId', 'isActive'])
@Index('idx_product_context_override_valid', ['validFrom', 'validUntil'])
export class ProductContextOverride {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'product_id', type: 'uuid' })
  productId: string;

  @ManyToOne(() => Product, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'product_id' })
  product: Product;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

  @Column({ type: 'int', default: 0 })
  priority: number;

  @Column({ name: 'valid_from', type: 'timestamptz', nullable: true })
  validFrom?: Date;

  @Column({ name: 'valid_until', type: 'timestamptz', nullable: true })
  validUntil?: Date;

  @Column({
    name: 'match_context',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  matchContext: Record<string, unknown>;

  @Column({ name: 'rule', type: 'jsonb', nullable: true })
  rule?: Record<string, unknown>;

  @Column({ name: 'patch', type: 'jsonb', default: () => "'[]'::jsonb" })
  patch: Array<Record<string, unknown>>;

  @Column({ name: 'description', type: 'text', nullable: true })
  description?: string;

  @Column({ name: 'audit', type: 'jsonb', default: () => "'{}'::jsonb" })
  audit: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
