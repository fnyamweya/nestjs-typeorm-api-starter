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
import { PromotionActionType } from './promotion.enums';

@Entity('promotion_action')
export class PromotionAction {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'promotion_id', type: 'uuid' })
  promotionId: string;

  @ManyToOne(() => Promotion, (p) => p.actions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'promotion_id' })
  promotion: Promotion;

  @Index()
  @Column({ type: 'enum', enum: PromotionActionType })
  type: PromotionActionType;

  @Column({ type: 'jsonb' })
  params: Record<string, unknown>;

  @Column({ type: 'jsonb', default: () => "'{}'::jsonb" })
  target: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
