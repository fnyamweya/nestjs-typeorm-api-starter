import {
  Column,
  CreateDateColumn,
  Entity,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { FeatureFlagOverride } from './feature-flag-override.entity';
import { FeatureFlagAudit } from './feature-flag-audit.entity';

export enum FeatureFlagType {
  BOOLEAN = 'boolean',
  PERCENTAGE = 'percentage',
  CONFIG = 'config',
}

export enum FeatureFlagStatus {
  ACTIVE = 'ACTIVE',
  DEPRECATED = 'DEPRECATED',
  REMOVED = 'REMOVED',
}

@Entity('feature_flags')
export class FeatureFlag {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @Column({ length: 100, unique: true })
  key: string;

  @Column({ length: 150 })
  name: string;

  @Column({ type: 'text', nullable: true })
  description?: string;

  @Column({ type: 'enum', enum: FeatureFlagType, default: FeatureFlagType.BOOLEAN })
  type: FeatureFlagType;

  @Column({ name: 'enabled_default', default: false })
  enabledDefault: boolean;

  @Column({ type: 'enum', enum: FeatureFlagStatus, default: FeatureFlagStatus.ACTIVE })
  status: FeatureFlagStatus;

  @Column({ name: 'group_key', length: 50, nullable: true })
  groupKey?: string;

  @Column({ type: 'text', array: true, nullable: true })
  tags?: string[];

  @Column({ name: 'created_by', length: 100, nullable: true })
  createdBy?: string;

  @Column({ name: 'updated_by', length: 100, nullable: true })
  updatedBy?: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @OneToMany(() => FeatureFlagOverride, (override) => override.featureFlag, {
    cascade: false,
  })
  overrides: FeatureFlagOverride[];

  @OneToMany(() => FeatureFlagAudit, (audit) => audit.featureFlag, {
    cascade: false,
  })
  audits: FeatureFlagAudit[];
}
