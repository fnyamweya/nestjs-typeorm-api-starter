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
import { ShippingMethod } from '../../shipping/entities/shipping-method.entity';
import { Location } from '../../location/entities/location.entity';
import { Currency } from '../../catalog/entities/currency.entity';
import { OrderFulfillmentStatus } from '../order-fulfillment.types';
import { FulfillmentPackage } from './fulfillment-package.entity';
import { FulfillmentItem } from './fulfillment-item.entity';

@Entity('order_fulfillment')
export class OrderFulfillment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index()
  @Column({ name: 'order_id', type: 'uuid' })
  orderId: string;

  @ManyToOne(() => Order, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'order_id' })
  order?: Order;

  @Index()
  @Column({ type: 'text', default: OrderFulfillmentStatus.PACKED })
  status: OrderFulfillmentStatus;

  @Index()
  @Column({ name: 'shipping_method_id', type: 'uuid', nullable: true })
  shippingMethodId?: string | null;

  @ManyToOne(() => ShippingMethod, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'shipping_method_id' })
  shippingMethod?: ShippingMethod;

  // Snapshot of shipping method fields at time of fulfillment
  @Column({
    name: 'shipping_method_snapshot_json',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  shippingMethodSnapshotJson: Record<string, unknown>;

  @Column({ name: 'tracking_number', type: 'text', nullable: true })
  trackingNumber?: string;

  @Column({ name: 'tracking_url', type: 'text', nullable: true })
  trackingUrl?: string;

  @Index()
  @Column({ name: 'origin_location_id', type: 'uuid', nullable: true })
  originLocationId?: string | null;

  @ManyToOne(() => Location, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'origin_location_id' })
  originLocation?: Location;

  @Column({ name: 'origin_name', type: 'text', nullable: true })
  originName?: string;

  // Snapshot of destination (customer shipping address) at fulfillment time
  @Column({ name: 'destination_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  destinationJson: Record<string, unknown>;

  @Index()
  @Column({ name: 'currency_code', type: 'char', length: 3 })
  currencyCode: string;

  @ManyToOne(() => Currency, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'currency_code', referencedColumnName: 'code' })
  currency?: Currency;

  @Column({ name: 'shipping_amount', type: 'numeric', precision: 18, scale: 4, default: 0 })
  shippingAmount: string;

  @Column({ name: 'insurance_amount', type: 'numeric', precision: 18, scale: 4, default: 0 })
  insuranceAmount: string;

  @Column({ name: 'packed_at', type: 'timestamptz', nullable: true })
  packedAt?: Date;

  @Column({ name: 'shipped_at', type: 'timestamptz', nullable: true })
  shippedAt?: Date;

  @Column({ name: 'delivered_at', type: 'timestamptz', nullable: true })
  deliveredAt?: Date;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(() => FulfillmentPackage, (p) => p.fulfillment)
  packages?: FulfillmentPackage[];

  @OneToMany(() => FulfillmentItem, (i) => i.fulfillment)
  fulfillmentItems?: FulfillmentItem[];
}
