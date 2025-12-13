import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { PriceList } from 'src/catalog/entities/price-list.entity';
import { Currency } from 'src/catalog/entities/currency.entity';
import { OrderItem } from './order-item.entity';
import { OrderLevelCharge } from './order-level-charge.entity';

export enum OrderStatus {
  PENDING = 'pending',
  CONFIRMED = 'confirmed',
  CANCELLED = 'cancelled',
  COMPLETED = 'completed',
}

export enum FinancialStatus {
  UNPAID = 'unpaid',
  AUTHORIZED = 'authorized',
  PAID = 'paid',
  REFUNDED = 'refunded',
}

export enum FulfillmentStatus {
  UNFULFILLED = 'unfulfilled',
  PARTIAL = 'partial',
  FULFILLED = 'fulfilled',
  RETURNED = 'returned',
}

@Entity('order')
export class Order {
  @PrimaryGeneratedColumn('increment', { type: 'bigint' })
  id: string;

  @Column({ name: 'order_number', type: 'text', unique: true })
  orderNumber: string;

  @Column({ name: 'external_id', type: 'text', nullable: true })
  externalId?: string;

  @Column({ name: 'customer_id', type: 'uuid', nullable: true })
  customerId?: string;

  @Column({ name: 'customer_email', type: 'text' })
  customerEmail: string;

  @Column({ name: 'customer_name', type: 'text', nullable: true })
  customerName?: string;

  @Column({ name: 'price_list_id', type: 'bigint' })
  priceListId: string;

  @ManyToOne(() => PriceList, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'price_list_id' })
  priceList: PriceList;

  @Column({ name: 'currency_code', type: 'char', length: 3 })
  currencyCode: string;

  @ManyToOne(() => Currency, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'currency_code', referencedColumnName: 'code' })
  currency: Currency;

  @Column({ name: 'locale', type: 'text', nullable: true })
  locale?: string;

  @Column({ name: 'sales_channel_code', type: 'text', nullable: true })
  salesChannelCode?: string;

  @Column({ name: 'ip_address', type: 'inet', nullable: true })
  ipAddress?: string;

  @Column({ name: 'user_agent', type: 'text', nullable: true })
  userAgent?: string;

  @Column({ type: 'text', default: OrderStatus.PENDING })
  status: OrderStatus;

  @Column({ name: 'financial_status', type: 'text', default: FinancialStatus.UNPAID })
  financialStatus: FinancialStatus;

  @Column({ name: 'fulfillment_status', type: 'text', default: FulfillmentStatus.UNFULFILLED })
  fulfillmentStatus: FulfillmentStatus;

  @Column({ name: 'risk_state', type: 'text', nullable: true })
  riskState?: string;

  @Column({ name: 'items_subtotal', type: 'numeric', precision: 18, scale: 4, default: 0 })
  itemsSubtotal: string;

  @Column({ name: 'discount_total', type: 'numeric', precision: 18, scale: 4, default: 0 })
  discountTotal: string;

  @Column({ name: 'fee_total', type: 'numeric', precision: 18, scale: 4, default: 0 })
  feeTotal: string;

  @Column({ name: 'tax_total', type: 'numeric', precision: 18, scale: 4, default: 0 })
  taxTotal: string;

  @Column({ name: 'shipping_subtotal', type: 'numeric', precision: 18, scale: 4, default: 0 })
  shippingSubtotal: string;

  @Column({ name: 'shipping_discount', type: 'numeric', precision: 18, scale: 4, default: 0 })
  shippingDiscount: string;

  @Column({ name: 'shipping_tax', type: 'numeric', precision: 18, scale: 4, default: 0 })
  shippingTax: string;

  @Column({ name: 'shipping_total', type: 'numeric', precision: 18, scale: 4, default: 0 })
  shippingTotal: string;

  @Column({ name: 'grand_total', type: 'numeric', precision: 18, scale: 4, default: 0 })
  grandTotal: string;

  @Column({ name: 'item_count', type: 'int', default: 0 })
  itemCount: number;

  @Column({ name: 'notes_customer', type: 'text', nullable: true })
  notesCustomer?: string;

  @Column({ name: 'notes_internal', type: 'text', nullable: true })
  notesInternal?: string;

  @Column({ type: 'text', array: true, nullable: true })
  tags?: string[];

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @Column({ name: 'placed_at', type: 'timestamptz', nullable: true })
  placedAt?: Date;

  @Column({ name: 'confirmed_at', type: 'timestamptz', nullable: true })
  confirmedAt?: Date;

  @Column({ name: 'cancelled_at', type: 'timestamptz', nullable: true })
  cancelledAt?: Date;

  @Column({ name: 'completed_at', type: 'timestamptz', nullable: true })
  completedAt?: Date;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(() => OrderItem, (item) => item.order)
  items: OrderItem[];

  @OneToMany(() => OrderLevelCharge, (charge) => charge.order)
  orderLevelCharges: OrderLevelCharge[];
}
