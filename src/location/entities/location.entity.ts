import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  PrimaryGeneratedColumn,
  Tree,
  TreeChildren,
  TreeParent,
  UpdateDateColumn,
} from 'typeorm';

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
export class Location {
  @PrimaryGeneratedColumn('uuid')
  id: string;

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
  type: LocationType;

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
