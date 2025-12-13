import { Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { Order } from './order.entity';

@Entity('order_level_charge')
export class OrderLevelCharge {
  @PrimaryGeneratedColumn('increment', { type: 'bigint' })
  id: string;

  @Column({ name: 'order_id', type: 'bigint' })
  orderId: string;

  @ManyToOne(() => Order, (order) => order.orderLevelCharges, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'order_id' })
  order: Order;

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

  @Column({ type: 'numeric', precision: 18, scale: 4 })
  amount: string;

  @Column({ name: 'is_included_in_price', type: 'boolean', default: false })
  isIncludedInPrice: boolean;

  @Column({ name: 'applies_to_shipping', type: 'boolean', default: false })
  appliesToShipping: boolean;

  @Column({ name: 'source_type', type: 'text', nullable: true })
  sourceType?: string;

  @Column({ name: 'source_reference', type: 'text', nullable: true })
  sourceReference?: string;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
