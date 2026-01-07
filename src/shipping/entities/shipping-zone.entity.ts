import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { ShippingZoneLocation } from './shipping-zone-location.entity';
import { ShippingZoneMethod } from './shipping-zone-method.entity';

@Entity('shipping_zone')
export class ShippingZone {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text', unique: true })
  code: string;

  @Column({ type: 'text' })
  name: string;

  @Column({ type: 'text', nullable: true })
  description?: string;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

  @OneToMany(() => ShippingZoneLocation, (l) => l.zone)
  locations: ShippingZoneLocation[];

  @OneToMany(() => ShippingZoneMethod, (zm) => zm.zone)
  zoneMethods: ShippingZoneMethod[];

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
