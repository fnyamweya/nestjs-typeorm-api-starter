import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryColumn,
} from 'typeorm';
import { PaymentMethod } from './payment-method.entity';
import { Channel } from '../../channels/entities/channel.entity';

@Entity('payment_method_channel')
@Index('idx_payment_method_channel_active', ['paymentMethodId', 'isActive'])
export class PaymentMethodChannel {
  @PrimaryColumn({ name: 'payment_method_id', type: 'uuid' })
  paymentMethodId: string;

  @PrimaryColumn({ name: 'channel_id', type: 'uuid' })
  channelId: string;

  @ManyToOne(() => PaymentMethod, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'payment_method_id' })
  paymentMethod: PaymentMethod;

  @ManyToOne(() => Channel, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'channel_id' })
  channel: Channel;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;
}
