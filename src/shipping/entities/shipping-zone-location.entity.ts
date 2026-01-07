import {
  Column,
  Entity,
  PrimaryGeneratedColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { ShippingZone } from './shipping-zone.entity';
import { Location } from '../../location/entities/location.entity';

export type ShippingLocationType =
  | 'location'
  | 'country'
  | 'region'
  | 'postal_code'
  | 'radius';

@Entity('shipping_zone_location')
export class ShippingZoneLocation {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'zone_id', type: 'uuid' })
  zoneId: string;

  @ManyToOne(() => ShippingZone, (z) => z.locations, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'zone_id' })
  zone: ShippingZone;

  @Column({ name: 'type', type: 'text' })
  type: ShippingLocationType;

  // Preferred mapping: link a zone to a Location tree node.
  // We keep legacy country/region/postal_code columns for backward compatibility.
  @Column({ name: 'location_id', type: 'uuid', nullable: true })
  locationId?: string;

  @ManyToOne(() => Location, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'location_id' })
  location?: Location;

  @Column({ name: 'country_code', type: 'char', length: 2, nullable: true })
  countryCode?: string;

  @Column({ name: 'region', type: 'text', nullable: true })
  region?: string;

  @Column({ name: 'postal_code', type: 'text', nullable: true })
  postalCode?: string;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;
}
