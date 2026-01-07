import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Promotion } from './promotion.entity';
import { ConditionOperator, PromotionConditionType } from './promotion.enums';

@Entity('promotion_condition')
export class PromotionCondition {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'promotion_id', type: 'uuid' })
  promotionId: string;

  @ManyToOne(() => Promotion, (p) => p.conditions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'promotion_id' })
  promotion: Promotion;

  @Index()
  @Column({ type: 'enum', enum: PromotionConditionType })
  type: PromotionConditionType;

  @Column({ type: 'enum', enum: ConditionOperator })
  operator: ConditionOperator;

  @Column({ type: 'jsonb' })
  params: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
