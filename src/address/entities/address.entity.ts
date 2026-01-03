import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('address')
export class Address {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'first_name', type: 'text', nullable: true })
  firstName?: string;

  @Column({ name: 'last_name', type: 'text', nullable: true })
  lastName?: string;

  @Column({ name: 'phone', type: 'text', nullable: true })
  phone?: string;

  @Column({ name: 'country_code', type: 'char', length: 2 })
  countryCode: string;

  @Column({ name: 'location_id', type: 'uuid', nullable: true })
  locationId?: string;

  // Dynamic address payload (country-specific)
  @Column({ name: 'fields_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  fieldsJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
