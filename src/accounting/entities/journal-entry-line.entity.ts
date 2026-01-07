import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { AccountingAccount } from './accounting-account.entity';
import { JournalEntry } from './journal-entry.entity';

@Entity('journal_entry_line')
@Index('idx_journal_entry_line_entry', ['entryId'])
@Index('idx_journal_entry_line_account', ['accountId'])
export class JournalEntryLine {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'entry_id', type: 'uuid' })
  entryId: string;

  @ManyToOne(() => JournalEntry, (entry) => entry.lines, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'entry_id' })
  entry: JournalEntry;

  @Column({ name: 'account_id', type: 'uuid' })
  accountId: string;

  @ManyToOne(() => AccountingAccount, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'account_id' })
  account: AccountingAccount;

  @Column({ type: 'numeric', precision: 18, scale: 4, default: 0 })
  debit: string;

  @Column({ type: 'numeric', precision: 18, scale: 4, default: 0 })
  credit: string;

  @Column({ name: 'currency_code', type: 'char', length: 3 })
  currencyCode: string;

  @Column({ type: 'text', nullable: true })
  memo?: string;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
