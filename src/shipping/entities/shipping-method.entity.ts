import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  ManyToOne,
  OneToMany,
  JoinColumn,
} from 'typeorm';
import { ShippingZone } from './shipping-zone.entity';
import { ShippingRate } from './shipping-rate.entity';
import { ShippingProvider } from './shipping-provider.entity';

@Entity('shipping_method')
export class ShippingMethod {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  // Legacy: prior schema bound methods directly to a zone.
  // Now methods are global and attached to zones via shipping_zone_method.
  @Column({ name: 'zone_id', type: 'uuid', nullable: true })
  zoneId?: string;

  @ManyToOne(() => ShippingZone, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'zone_id' })
  zone?: ShippingZone;

  @Column({ name: 'provider_id', type: 'uuid', nullable: true })
  providerId?: string;

  @ManyToOne(() => ShippingProvider, (p) => p.methods, {
    nullable: true,
    onDelete: 'SET NULL',
  })
  @JoinColumn({ name: 'provider_id' })
  providerEntity?: ShippingProvider;

  @Column({ type: 'text' })
  code: string;

  @Column({ name: 'display_name', type: 'text' })
  displayName: string;

  @Column({ name: 'provider', type: 'text', nullable: true })
  provider?: string;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

  @OneToMany(() => ShippingRate, (r) => r.method)
  rates: ShippingRate[];

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
