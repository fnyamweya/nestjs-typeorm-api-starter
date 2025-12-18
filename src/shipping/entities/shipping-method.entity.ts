import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn, ManyToOne, OneToMany, JoinColumn } from 'typeorm';
import { ShippingZone } from './shipping-zone.entity';
import { ShippingRate } from './shipping-rate.entity';

@Entity('shipping_method')
export class ShippingMethod {
  @PrimaryGeneratedColumn('increment', { type: 'bigint' })
  id: string;

  @Column({ name: 'zone_id', type: 'bigint' })
  zoneId: string;

  @ManyToOne(() => ShippingZone, (z) => z.methods, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'zone_id' })
  zone: ShippingZone;

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
