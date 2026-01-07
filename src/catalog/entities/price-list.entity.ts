import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

export type PriceListStatus = 'active' | 'inactive' | 'archived';
export type PriceListStackingPolicy = 'EXCLUSIVE' | 'STACKABLE';
export type PriceListMatchPolicy =
  | 'HIGHEST_PRIORITY'
  | 'LOWEST_PRICE'
  | 'FIRST_MATCH';

@Entity('price_list')
export class PriceList {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text', unique: true })
  code: string;

  @Column({ type: 'text' })
  name: string;

  @Column({ name: 'currency_code', type: 'char', length: 3 })
  currency: string;

  @Column({ name: 'priority', type: 'int', default: 0 })
  priority: number;

  @Column({ name: 'scope_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  scope: Record<string, unknown>;

  @Column({ name: 'status', type: 'text', default: 'active' })
  status: PriceListStatus;

  @Column({ name: 'stacking_policy', type: 'text', default: 'EXCLUSIVE' })
  stackingPolicy: PriceListStackingPolicy;

  @Column({ name: 'match_policy', type: 'text', default: 'HIGHEST_PRIORITY' })
  matchPolicy: PriceListMatchPolicy;

  @Column({ name: 'stop_after_match', type: 'boolean', default: true })
  stopAfterMatch: boolean;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
