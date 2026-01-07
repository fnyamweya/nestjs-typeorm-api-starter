import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { OrderFulfillment } from './order-fulfillment.entity';
import { PackageItem } from './package-item.entity';

@Entity('fulfillment_package')
export class FulfillmentPackage {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index()
  @Column({ name: 'fulfillment_id', type: 'uuid' })
  fulfillmentId: string;

  @ManyToOne(() => OrderFulfillment, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'fulfillment_id' })
  fulfillment?: OrderFulfillment;

  @Column({ name: 'weight_value', type: 'numeric', precision: 18, scale: 4, nullable: true })
  weightValue?: string;

  @Column({ name: 'weight_unit', type: 'text', nullable: true })
  weightUnit?: string;

  @Column({ name: 'dim_length', type: 'numeric', precision: 18, scale: 4, nullable: true })
  dimLength?: string;

  @Column({ name: 'dim_width', type: 'numeric', precision: 18, scale: 4, nullable: true })
  dimWidth?: string;

  @Column({ name: 'dim_height', type: 'numeric', precision: 18, scale: 4, nullable: true })
  dimHeight?: string;

  @Column({ name: 'dim_unit', type: 'text', nullable: true })
  dimUnit?: string;

  @Column({ name: 'tracking_number', type: 'text', nullable: true })
  trackingNumber?: string;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(() => PackageItem, (pi) => pi.pkg)
  packageItems?: PackageItem[];
}
