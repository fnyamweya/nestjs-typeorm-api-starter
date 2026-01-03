import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('address_field_config')
@Index('uq_address_field_config_country_active', ['countryCode', 'isActive'], {
  unique: true,
})
export class AddressFieldConfig {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'country_code', type: 'char', length: 2 })
  countryCode: string;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

  @Column({ name: 'schema_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  schemaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
