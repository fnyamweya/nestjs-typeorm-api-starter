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
import { CustomerTier } from './customer-tier.entity';

@Entity('customer_tier_rule')
@Index('idx_customer_tier_rule_active', ['isActive', 'priority'])
export class CustomerTierRule {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'tier_id', type: 'uuid' })
  tierId: string;

  @ManyToOne(() => CustomerTier, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'tier_id' })
  tier: CustomerTier;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

  @Column({ type: 'int', default: 0 })
  priority: number;

  @Column({ name: 'valid_from', type: 'timestamptz', nullable: true })
  validFrom?: Date;

  @Column({ name: 'valid_until', type: 'timestamptz', nullable: true })
  validUntil?: Date;

  @Column({ name: 'rule_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  ruleJson: Record<string, unknown>;

  @Column({ type: 'text', nullable: true })
  description?: string;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
