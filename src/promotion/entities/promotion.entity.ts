import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

export type PromotionType = 'percentage' | 'fixed' | 'free_shipping';

@Entity('promotion')
export class Promotion {
  @PrimaryGeneratedColumn('increment', { type: 'bigint' })
  id: string;

  @Column({ type: 'text', unique: true })
  code: string;

  @Column({ type: 'text', nullable: true })
  description?: string;

  @Column({ type: 'text' })
  type: PromotionType;

  // percentage e.g. 10 for 10% or fixed amount string numeric
  @Column({ name: 'value', type: 'numeric', precision: 12, scale: 2, default: 0 })
  value: string;

  @Column({ name: 'currency_code', type: 'char', length: 3, nullable: true })
  currencyCode?: string;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

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
