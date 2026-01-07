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

@Entity('promotion_redemption')
export class PromotionRedemption {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'promotion_id', type: 'uuid' })
  promotionId: string;

  @ManyToOne(() => Promotion, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'promotion_id' })
  promotion: Promotion;

  @Index()
  @Column({ name: 'customer_id', type: 'uuid', nullable: true })
  customerId?: string;

  @Index()
  @Column({ name: 'order_id', type: 'uuid', nullable: true })
  orderId?: string;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
