import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('banner')
@Index('idx_banner_is_active', ['isActive'])
@Index('idx_banner_starts_at', ['startsAt'])
@Index('idx_banner_ends_at', ['endsAt'])
export class Banner {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text' })
  name: string;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

  @Column({ name: 'starts_at', type: 'timestamptz', nullable: true })
  startsAt?: Date | null;

  @Column({ name: 'ends_at', type: 'timestamptz', nullable: true })
  endsAt?: Date | null;

  @Column({ type: 'int', default: 0 })
  priority: number;

  @Column({
    name: 'creative_json',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  creativeJson: Record<string, unknown>;

  @Column({
    name: 'placements_json',
    type: 'jsonb',
    default: () => "'[]'::jsonb",
  })
  placementsJson: Array<Record<string, unknown>>;

  @Column({ name: 'targets_json', type: 'jsonb', default: () => "'[]'::jsonb" })
  targetsJson: Array<Record<string, unknown>>;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
