import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn, UpdateDateColumn, OneToMany } from 'typeorm';
import { ShippingZoneLocation } from './shipping-zone-location.entity';
import { ShippingMethod } from './shipping-method.entity';

@Entity('shipping_zone')
export class ShippingZone {
  @PrimaryGeneratedColumn('increment', { type: 'bigint' })
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

  @OneToMany(() => ShippingMethod, (m) => m.zone)
  methods: ShippingMethod[];

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
