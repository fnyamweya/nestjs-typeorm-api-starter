import { Column, Entity, PrimaryGeneratedColumn, ManyToOne, JoinColumn } from 'typeorm';
import { ShippingZone } from './shipping-zone.entity';

export type ShippingLocationType = 'country' | 'region' | 'postal_code' | 'radius';

@Entity('shipping_zone_location')
export class ShippingZoneLocation {
  @PrimaryGeneratedColumn('increment', { type: 'bigint' })
  id: string;

  @Column({ name: 'zone_id', type: 'bigint' })
  zoneId: string;

  @ManyToOne(() => ShippingZone, (z) => z.locations, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'zone_id' })
  zone: ShippingZone;

  @Column({ name: 'type', type: 'text' })
  type: ShippingLocationType;

  @Column({ name: 'country_code', type: 'char', length: 2, nullable: true })
  countryCode?: string;

  @Column({ name: 'region', type: 'text', nullable: true })
  region?: string;

  @Column({ name: 'postal_code', type: 'text', nullable: true })
  postalCode?: string;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;
}
