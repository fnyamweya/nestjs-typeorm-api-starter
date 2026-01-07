import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Order } from '../../order/entities/order.entity';
import { Currency } from '../../catalog/entities/currency.entity';
import { OrderPaymentStatus, OrderPaymentType } from '../order-payment.types';
import { PaymentAllocation } from './payment-allocation.entity';

@Entity('order_payment')
export class OrderPayment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index()
  @Column({ name: 'order_id', type: 'uuid' })
  orderId: string;

  @ManyToOne(() => Order, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'order_id' })
  order?: Order;

  @Index()
  @Column({ type: 'text' })
  type: OrderPaymentType;

  @Index()
  @Column({ type: 'text', default: OrderPaymentStatus.PENDING })
  status: OrderPaymentStatus;

  @Index()
  @Column({ type: 'text' })
  provider: string;

  @Index()
  @Column({ type: 'text' })
  method: string;

  @Column({ type: 'numeric', precision: 18, scale: 4 })
  amount: string;

  @Index()
  @Column({ name: 'currency_code', type: 'char', length: 3 })
  currencyCode: string;

  @ManyToOne(() => Currency, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'currency_code', referencedColumnName: 'code' })
  currency?: Currency;

  @Index()
  @Column({ name: 'external_ref', type: 'text', nullable: true })
  externalRef?: string;

  @Column({ name: 'initiated_at', type: 'timestamptz', nullable: true })
  initiatedAt?: Date;

  @Column({ name: 'confirmed_at', type: 'timestamptz', nullable: true })
  confirmedAt?: Date;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(() => PaymentAllocation, (a) => a.payment)
  allocations?: PaymentAllocation[];
}
