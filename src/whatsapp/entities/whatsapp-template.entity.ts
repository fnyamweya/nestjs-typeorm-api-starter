import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('whatsapp_template')
@Index('uq_whatsapp_template_name', ['name'], { unique: true })
export class WhatsappTemplate {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text' })
  name: string;

  @Column({ type: 'text', default: 'en_US' })
  language: string;

  @Column({ type: 'text' })
  category: string;

  @Column({ type: 'text', default: 'draft' })
  status: string;

  @Column({ name: 'provider_template_id', type: 'text', nullable: true })
  providerTemplateId?: string;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

  @Column({
    name: 'components_json',
    type: 'jsonb',
    default: () => "'[]'::jsonb",
  })
  componentsJson: Array<Record<string, unknown>>;

  @Column({
    name: 'default_components_json',
    type: 'jsonb',
    default: () => "'[]'::jsonb",
  })
  defaultComponentsJson: Array<Record<string, unknown>>;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
