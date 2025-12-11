import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';

@Entity('attribute_definition')
@Index('uq_attribute_code', ['code'], { unique: true })
export class AttributeDefinition {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text', nullable: false })
  code: string;

  @Column({ type: 'text', nullable: false })
  label: string;

  @Column({ name: 'value_type', type: 'text', nullable: false })
  valueType: string;

  @Column({ name: 'is_facet', type: 'boolean', default: false })
  isFacet: boolean;

  @Column({ name: 'is_searchable', type: 'boolean', default: false })
  isSearchable: boolean;

  @Column({ name: 'is_variant_axis', type: 'boolean', default: false })
  isVariantAxis: boolean;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;
}
