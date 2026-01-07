import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { PromotionAction } from './promotion-action.entity';
import { PromotionCondition } from './promotion-condition.entity';
import { PromotionStatus, StackingPolicy } from './promotion.enums';

@Entity('promotion')
export class Promotion {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index({ unique: true })
  @Column({ type: 'text' })
  code: string;

  @Column({ type: 'text', nullable: true })
  name?: string;

  @Column({ type: 'text', nullable: true })
  description?: string;

  @Column({
    type: 'enum',
    enum: PromotionStatus,
    default: PromotionStatus.DRAFT,
  })
  status: PromotionStatus;

  @Column({ type: 'int', default: 100 })
  priority: number;

  @Column({
    name: 'stacking_policy',
    type: 'enum',
    enum: StackingPolicy,
    default: StackingPolicy.STACKABLE,
  })
  stackingPolicy: StackingPolicy;

  @Column({ name: 'stacking_group', type: 'text', nullable: true })
  stackingGroup?: string;

  @Column({ name: 'max_redemptions', type: 'int', nullable: true })
  maxRedemptions?: number;

  @Column({ name: 'max_redemptions_per_customer', type: 'int', nullable: true })
  maxRedemptionsPerCustomer?: number;

  @Column({ name: 'valid_from', type: 'timestamptz', nullable: true })
  validFrom?: Date;

  @Column({ name: 'valid_to', type: 'timestamptz', nullable: true })
  validTo?: Date;

  @Column({ type: 'jsonb', default: () => "'[]'::jsonb" })
  channels: string[];

  @Column({ type: 'jsonb', default: () => "'{}'::jsonb" })
  metadata: Record<string, unknown>;

  @OneToMany(() => PromotionCondition, (c) => c.promotion, { cascade: true })
  conditions: PromotionCondition[];

  @OneToMany(() => PromotionAction, (a) => a.promotion, { cascade: true })
  actions: PromotionAction[];

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
