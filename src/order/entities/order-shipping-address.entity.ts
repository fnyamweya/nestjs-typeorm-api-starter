import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Order } from './order.entity';

@Entity('order_shipping_address')
@Index('uq_order_shipping_address_order', ['orderId'], { unique: true })
export class OrderShippingAddress {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'order_id', type: 'uuid' })
  orderId: string;

  @ManyToOne(() => Order, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'order_id' })
  order: Order;

  // Snapshot fields (so the order is immutable even if the customer address changes)
  @Column({ name: 'first_name', type: 'text', nullable: true })
  firstName?: string;

  @Column({ name: 'last_name', type: 'text', nullable: true })
  lastName?: string;

  @Column({ name: 'phone', type: 'text', nullable: true })
  phone?: string;

  @Column({ name: 'country_code', type: 'char', length: 2, nullable: true })
  countryCode?: string;

  @Column({ name: 'location_id', type: 'uuid', nullable: true })
  locationId?: string;

  @Column({ name: 'fields_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  fieldsJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
