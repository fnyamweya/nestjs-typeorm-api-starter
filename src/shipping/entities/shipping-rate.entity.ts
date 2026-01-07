import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  ManyToOne,
  JoinColumn,
  JoinTable,
  ManyToMany,
} from 'typeorm';
import { ShippingMethod } from './shipping-method.entity';
import { Currency } from '../../catalog/entities/currency.entity';
import { Channel } from '../../channels/entities/channel.entity';

export type ShippingCalculationType =
  | 'flat'
  | 'per_weight'
  | 'per_item'
  | 'table_rate'
  | 'formula';

@Entity('shipping_rate')
export class ShippingRate {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'method_id', type: 'uuid' })
  methodId: string;

  @ManyToOne(() => ShippingMethod, (m) => m.rates, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'method_id' })
  method: ShippingMethod;

  @Column({ name: 'calculation_type', type: 'text' })
  calculationType: ShippingCalculationType;

  // numeric thresholds and values used depending on calculation type
  @Column({
    name: 'min_weight',
    type: 'numeric',
    precision: 12,
    scale: 4,
    nullable: true,
  })
  minWeight?: string;

  @Column({
    name: 'max_weight',
    type: 'numeric',
    precision: 12,
    scale: 4,
    nullable: true,
  })
  maxWeight?: string;

  @Column({
    name: 'min_subtotal',
    type: 'numeric',
    precision: 18,
    scale: 4,
    nullable: true,
  })
  minSubtotal?: string;

  @Column({
    name: 'max_subtotal',
    type: 'numeric',
    precision: 18,
    scale: 4,
    nullable: true,
  })
  maxSubtotal?: string;

  @Column({ name: 'price', type: 'numeric', precision: 18, scale: 4 })
  price: string;

  @Column({
    name: 'price_per_unit',
    type: 'numeric',
    precision: 18,
    scale: 6,
    nullable: true,
  })
  pricePerUnit?: string;

  @Column({ name: 'currency_code', type: 'char', length: 3, nullable: true })
  currencyCode?: string;

  @ManyToOne(() => Currency, { onDelete: 'RESTRICT', nullable: true })
  @JoinColumn({ name: 'currency_code', referencedColumnName: 'code' })
  currency?: Currency;

  @ManyToMany(() => Channel, { cascade: false })
  @JoinTable({
    name: 'shipping_rate_channel',
    joinColumn: { name: 'rate_id', referencedColumnName: 'id' },
    inverseJoinColumn: { name: 'channel_id', referencedColumnName: 'id' },
  })
  channels?: Channel[];

  @Column({ name: 'priority', type: 'int', default: 0 })
  priority: number;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
