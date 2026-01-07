import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { ShippingZone } from './shipping-zone.entity';
import { ShippingMethod } from './shipping-method.entity';

@Entity('shipping_zone_method')
@Index('uq_shipping_zone_method_zone_method', ['zoneId', 'shippingMethodId'], {
  unique: true,
})
@Index('idx_shipping_zone_method_zone', ['zoneId'])
@Index('idx_shipping_zone_method_method', ['shippingMethodId'])
export class ShippingZoneMethod {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'zone_id', type: 'uuid' })
  zoneId: string;

  @ManyToOne(() => ShippingZone, (z) => z.zoneMethods, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'zone_id' })
  zone: ShippingZone;

  @Column({ name: 'shipping_method_id', type: 'uuid' })
  shippingMethodId: string;

  @ManyToOne(() => ShippingMethod, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'shipping_method_id' })
  method: ShippingMethod;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
