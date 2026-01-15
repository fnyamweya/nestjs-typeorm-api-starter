import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  Tree,
  TreeChildren,
  TreeParent,
  UpdateDateColumn,
} from 'typeorm';
import { CountryConfig } from 'src/country/entities/country-config.entity';

export enum LocationType {
  COUNTRY = 'country',
  COUNTY = 'county',
  SUB_COUNTY = 'sub_county',
  WARD = 'ward',
  TOWN = 'town',
}

@Tree('closure-table')
@Entity('location')
@Index('idx_location_type', ['type'])
@Index('idx_location_country_code', ['countryCode'])
@Index('idx_location_country_id', ['countryId'])
export class Location {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'country_id', type: 'uuid' })
  countryId: string;

  @ManyToOne(() => CountryConfig, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'country_id' })
  country: CountryConfig;

  // For Kenya (and most cases), every row will have countryCode='KE'.
  // For the COUNTRY node itself, we still set countryCode.
  @Column({ name: 'country_code', type: 'char', length: 2, nullable: true })
  countryCode?: string;

  @Column({ type: 'text' })
  name: string;

  // Optional stable code (e.g. ISO2 for country, or internal code)
  @Column({ type: 'text', nullable: true })
  code?: string;

  @Column({ type: 'text' })
  type: string;

  @TreeParent()
  @JoinColumn({ name: 'parent_id' })
  parent?: Location;

  @TreeChildren()
  children: Location[];

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
