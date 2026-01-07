import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { OrderItem } from '../../order/entities/order-item.entity';
import { FulfillmentPackage } from './fulfillment-package.entity';

@Entity('package_item')
@Index('uq_package_item', ['packageId', 'orderItemId'], { unique: true })
export class PackageItem {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index()
  @Column({ name: 'package_id', type: 'uuid' })
  packageId: string;

  @ManyToOne(() => FulfillmentPackage, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'package_id' })
  pkg?: FulfillmentPackage;

  @Index()
  @Column({ name: 'order_item_id', type: 'uuid' })
  orderItemId: string;

  @ManyToOne(() => OrderItem, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'order_item_id' })
  orderItem?: OrderItem;

  @Column({ type: 'int' })
  quantity: number;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
