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
import { OrderItem } from '../../order/entities/order-item.entity';
import { OrderFulfillment } from './order-fulfillment.entity';

@Entity('order_fulfillment_item')
@Index('uq_order_fulfillment_item', ['fulfillmentId', 'orderItemId'], { unique: true })
export class FulfillmentItem {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index()
  @Column({ name: 'fulfillment_id', type: 'uuid' })
  fulfillmentId: string;

  @ManyToOne(() => OrderFulfillment, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'fulfillment_id' })
  fulfillment?: OrderFulfillment;

  @Index()
  @Column({ name: 'order_item_id', type: 'uuid' })
  orderItemId: string;

  @ManyToOne(() => OrderItem, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'order_item_id' })
  orderItem?: OrderItem;

  @Column({ type: 'int' })
  quantity: number;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
