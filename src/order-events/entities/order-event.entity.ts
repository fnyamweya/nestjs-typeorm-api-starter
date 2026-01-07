import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Order } from '../../order/entities/order.entity';
import { OrderEventTargetType } from '../order-events.types';

@Entity('order_event')
@Index('uq_order_event_idempotency', ['idempotencyKey'], { unique: true })
@Index('idx_order_event_order_created', ['orderId', 'createdAt'])
@Index('idx_order_event_target', ['targetType', 'targetId', 'createdAt'])
export class OrderEvent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index()
  @Column({ name: 'order_id', type: 'uuid' })
  orderId: string;

  @ManyToOne(() => Order, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'order_id' })
  order?: Order;

  @Column({ name: 'target_type', type: 'text' })
  targetType: OrderEventTargetType;

  @Column({ name: 'target_id', type: 'uuid' })
  targetId: string;

  // Convenience references (nullable, but indexed) to make filtering/querying easier.
  @Index()
  @Column({ name: 'order_item_id', type: 'uuid', nullable: true })
  orderItemId?: string | null;

  @Index()
  @Column({ name: 'fulfillment_id', type: 'uuid', nullable: true })
  fulfillmentId?: string | null;

  @Index()
  @Column({ name: 'package_id', type: 'uuid', nullable: true })
  packageId?: string | null;

  @Column({ type: 'text' })
  action: string;

  @Column({ name: 'idempotency_key', type: 'text' })
  idempotencyKey: string;

  @Column({ name: 'actor_type', type: 'text', nullable: true })
  actorType?: string | null;

  @Column({ name: 'actor_id', type: 'text', nullable: true })
  actorId?: string | null;

  @Column({ name: 'actor_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  actorJson: Record<string, unknown>;

  // Previous activity snapshot in the same row
  @Column({ name: 'previous_event_id', type: 'uuid', nullable: true })
  previousEventId?: string | null;

  @Column({ name: 'previous_action', type: 'text', nullable: true })
  previousAction?: string | null;

  @Column({ name: 'previous_created_at', type: 'timestamptz', nullable: true })
  previousCreatedAt?: Date | null;

  // Forward-looking guidance
  @Column({ name: 'next_action', type: 'text', nullable: true })
  nextAction?: string | null;

  @Column({ name: 'next_actions_json', type: 'jsonb', default: () => "'[]'::jsonb" })
  nextActionsJson: string[];

  @Column({ name: 'context_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  contextJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
