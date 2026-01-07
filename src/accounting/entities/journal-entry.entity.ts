import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { JournalEntryLine } from './journal-entry-line.entity';

@Entity('journal_entry')
@Index('uq_journal_entry_idempotency_key', ['idempotencyKey'], { unique: true })
@Index('idx_journal_entry_source', ['sourceType', 'sourceId'])
export class JournalEntry {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'source_type', type: 'text', nullable: true })
  sourceType?: string;

  @Column({ name: 'source_id', type: 'text', nullable: true })
  sourceId?: string;

  @Column({ name: 'idempotency_key', type: 'text' })
  idempotencyKey: string;

  @Column({ name: 'currency_code', type: 'char', length: 3 })
  currencyCode: string;

  @Column({ name: 'posted_at', type: 'timestamptz', default: () => 'now()' })
  postedAt: Date;

  @Column({ type: 'text', nullable: true })
  memo?: string;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @OneToMany(() => JournalEntryLine, (line) => line.entry)
  lines: JournalEntryLine[];
}
