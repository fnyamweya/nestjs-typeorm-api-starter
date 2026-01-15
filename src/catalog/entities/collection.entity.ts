import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { CollectionItem } from './collection-item.entity';

export enum CollectionRuleType {
  STATIC = 'STATIC',
  QUERY = 'QUERY',
}

export type CollectionRulePayload = {
  categoryIds?: string[];
  brandIds?: string[];
  productIds?: string[];
  limit?: number;
  sort?: 'newest' | '-newest';
};

@Entity('collection')
@Index('uq_collection_slug', ['slug'], { unique: true })
@Index('idx_collection_active_type', ['isActive', 'type'])
@Index('idx_collection_validity', ['validFrom', 'validTo'])
export class Collection {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text', nullable: false })
  title: string;

  @Column({ type: 'text', nullable: true })
  description?: string;

  @Column({ type: 'text', nullable: true })
  icon?: string;

  @Column({ name: 'avatar_url', type: 'text', nullable: true })
  avatarUrl?: string;

  @Column({ type: 'text', nullable: false })
  slug: string;

  @Column({ type: 'text', default: 'default' })
  type: string;

  @Column({ name: 'rule_type', type: 'text', default: CollectionRuleType.STATIC })
  ruleType: CollectionRuleType;

  @Column({
    name: 'rule_payload',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  rulePayload: CollectionRulePayload;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

  @Column({ type: 'integer', default: 0 })
  priority: number;

  @Column({ name: 'valid_from', type: 'timestamptz', nullable: true })
  validFrom?: Date;

  @Column({ name: 'valid_to', type: 'timestamptz', nullable: true })
  validTo?: Date;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(() => CollectionItem, (item) => item.collection)
  items: CollectionItem[];
}
