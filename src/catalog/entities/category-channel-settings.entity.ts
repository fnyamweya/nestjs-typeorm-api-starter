import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Category } from './category.entity';
import { SalesChannel } from './sales-channel.entity';

@Entity('category_channel_settings')
@Index('uq_category_channel', ['categoryId', 'channelId'], { unique: true })
@Index('idx_cat_channel_visible', ['channelId', 'isVisible'])
export class CategoryChannelSettings {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'category_id', type: 'uuid' })
  categoryId: string;

  @ManyToOne(() => Category, (category) => category.channelSettings, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'category_id' })
  category: Category;

  @Column({ name: 'channel_id', type: 'uuid' })
  channelId: string;

  @ManyToOne(() => SalesChannel, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'channel_id' })
  channel: SalesChannel;

  @Column({ name: 'is_visible', type: 'boolean', default: true })
  isVisible: boolean;

  @Column({ name: 'custom_sort_mode', type: 'text', nullable: true })
  customSortMode?: string;

  @Column({
    name: 'merchandising_json',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  merchandisingJson: Record<string, unknown>;
}
