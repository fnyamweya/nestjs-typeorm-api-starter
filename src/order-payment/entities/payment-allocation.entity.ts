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
import { Order } from '../../order/entities/order.entity';
import { OrderItem } from '../../order/entities/order-item.entity';
import { Currency } from '../../catalog/entities/currency.entity';
import { PaymentAllocationAppliesTo } from '../order-payment.types';
import { OrderPayment } from './order-payment.entity';

@Entity('payment_allocation')
export class PaymentAllocation {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index()
  @Column({ name: 'payment_id', type: 'uuid' })
  paymentId: string;

  @ManyToOne(() => OrderPayment, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'payment_id' })
  payment?: OrderPayment;

  @Index()
  @Column({ name: 'order_id', type: 'uuid' })
  orderId: string;

  @ManyToOne(() => Order, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'order_id' })
  order?: Order;

  @Index()
  @Column({ name: 'applies_to', type: 'text' })
  appliesTo: PaymentAllocationAppliesTo;

  @Index()
  @Column({ name: 'order_item_id', type: 'uuid', nullable: true })
  orderItemId?: string | null;

  @ManyToOne(() => OrderItem, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'order_item_id' })
  orderItem?: OrderItem;

  @Column({ type: 'numeric', precision: 18, scale: 4 })
  amount: string;

  @Index()
  @Column({ name: 'currency_code', type: 'char', length: 3 })
  currencyCode: string;

  @ManyToOne(() => Currency, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'currency_code', referencedColumnName: 'code' })
  currency?: Currency;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
