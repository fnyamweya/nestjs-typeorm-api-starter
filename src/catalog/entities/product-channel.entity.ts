import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryColumn,
} from 'typeorm';
import { Product } from './product.entity';
import { Channel } from '../../channels/entities/channel.entity';

@Entity('product_channel')
@Index('idx_product_channel_active', ['productId', 'isActive'])
export class ProductChannel {
  @PrimaryColumn({ name: 'product_id', type: 'uuid' })
  productId: string;

  @PrimaryColumn({ name: 'channel_id', type: 'uuid' })
  channelId: string;

  @ManyToOne(() => Product, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'product_id' })
  product: Product;

  @ManyToOne(() => Channel, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'channel_id' })
  channel: Channel;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;
}
