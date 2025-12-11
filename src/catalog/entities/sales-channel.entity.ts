import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('sales_channel')
export class SalesChannel {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text', unique: true })
  code: string;

  @Column({ type: 'text', nullable: false })
  name: string;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;
}
