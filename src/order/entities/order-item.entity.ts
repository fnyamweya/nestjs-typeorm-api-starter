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
import { Order } from './order.entity';
import { OrderItemCharge } from './order-item-charge.entity';

@Entity('order_item')
export class OrderItem {
  @PrimaryGeneratedColumn('increment', { type: 'bigint' })
  id: string;

  @Column({ name: 'order_id', type: 'bigint' })
  orderId: string;

  @ManyToOne(() => Order, (order) => order.items, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'order_id' })
  order: Order;

  @Column({ name: 'product_id', type: 'uuid', nullable: true })
  productId?: string;

  @Column({ name: 'product_variant_id', type: 'uuid', nullable: true })
  productVariantId?: string;

  @Column({ type: 'text', nullable: true })
  sku?: string;

  @Column({ name: 'product_handle', type: 'text', nullable: true })
  productHandle?: string;

  @Column({ name: 'product_name', type: 'text' })
  productName: string;

  @Column({ name: 'variant_title', type: 'text', nullable: true })
  variantTitle?: string;

  @Column({ name: 'variant_options_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  variantOptionsJson: Record<string, unknown>;

  @Column({ name: 'attributes_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  attributesJson: Record<string, unknown>;

  @Column({ type: 'int' })
  quantity: number;

  @Column({ name: 'price_list_id', type: 'bigint' })
  priceListId: string;

  @Column({ name: 'unit_price', type: 'numeric', precision: 18, scale: 4 })
  unitPrice: string;

  @Column({ name: 'compare_at_price', type: 'numeric', precision: 18, scale: 4, nullable: true })
  compareAtPrice?: string;

  @Column({ name: 'base_subtotal', type: 'numeric', precision: 18, scale: 4 })
  baseSubtotal: string;

  @Column({ name: 'discount_total', type: 'numeric', precision: 18, scale: 4, default: 0 })
  discountTotal: string;

  @Column({ name: 'fee_total', type: 'numeric', precision: 18, scale: 4, default: 0 })
  feeTotal: string;

  @Column({ name: 'tax_total', type: 'numeric', precision: 18, scale: 4, default: 0 })
  taxTotal: string;

  @Column({ type: 'numeric', precision: 18, scale: 4 })
  total: string;

  @Column({ name: 'requires_shipping', type: 'boolean', default: true })
  requiresShipping: boolean;

  @Column({ name: 'fulfillment_status', type: 'text', default: 'unfulfilled' })
  fulfillmentStatus: string;

  @Column({ name: 'fulfillment_group', type: 'text', nullable: true })
  fulfillmentGroup?: string;

  @Column({ name: 'pricing_snapshot_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  pricingSnapshotJson: Record<string, unknown>;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(() => OrderItemCharge, (charge) => charge.orderItem)
  itemCharges: OrderItemCharge[];
}
