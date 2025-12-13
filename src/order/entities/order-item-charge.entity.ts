import { Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { OrderItem } from './order-item.entity';

@Entity('order_item_charge')
export class OrderItemCharge {
  @PrimaryGeneratedColumn('increment', { type: 'bigint' })
  id: string;

  @Column({ name: 'order_item_id', type: 'bigint' })
  orderItemId: string;

  @ManyToOne(() => OrderItem, (item) => item.itemCharges, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'order_item_id' })
  orderItem: OrderItem;

  @Column({ name: 'charge_kind', type: 'text' })
  chargeKind: string;

  @Column({ type: 'text', nullable: true })
  code?: string;

  @Column({ name: 'display_name', type: 'text' })
  displayName: string;

  @Column({ name: 'calculation_type', type: 'text' })
  calculationType: string;

  @Column({ type: 'numeric', precision: 9, scale: 6, nullable: true })
  rate?: string;

  @Column({ name: 'base_amount', type: 'numeric', precision: 18, scale: 4, nullable: true })
  baseAmount?: string;

  @Column({ name: 'quantity_basis', type: 'int', nullable: true })
  quantityBasis?: number;

  @Column({ type: 'numeric', precision: 18, scale: 4 })
  amount: string;

  @Column({ name: 'is_included_in_price', type: 'boolean', default: false })
  isIncludedInPrice: boolean;

  @Column({ name: 'source_type', type: 'text', nullable: true })
  sourceType?: string;

  @Column({ name: 'source_reference', type: 'text', nullable: true })
  sourceReference?: string;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
