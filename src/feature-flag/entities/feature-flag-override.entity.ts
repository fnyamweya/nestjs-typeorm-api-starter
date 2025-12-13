import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { FeatureFlag } from './feature-flag.entity';
import { FeatureSegment } from './feature-segment.entity';

export enum FeatureFlagTargetType {
  USER = 'USER',
  ROLE = 'ROLE',
  TENANT = 'TENANT',
  ENV = 'ENV',
}

@Entity('feature_flag_overrides')
export class FeatureFlagOverride {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @ManyToOne(() => FeatureFlag, (flag) => flag.overrides, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'feature_flag_id' })
  featureFlag: FeatureFlag;

  @Column({ name: 'feature_flag_id', type: 'bigint' })
  featureFlagId: string;

  @Column({ name: 'target_type', type: 'enum', enum: FeatureFlagTargetType })
  targetType: FeatureFlagTargetType;

  @Column({ name: 'target_id', length: 100, nullable: true })
  targetId?: string;

  @Column({ length: 50, nullable: true })
  env?: string;

  @ManyToOne(() => FeatureSegment, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'segment_id' })
  segment?: FeatureSegment;

  @Column({ name: 'segment_id', type: 'bigint', nullable: true })
  segmentId?: string;

  @Column({ name: 'value_boolean', type: 'boolean', nullable: true })
  valueBoolean?: boolean;

  @Column({ name: 'value_json', type: 'jsonb', nullable: true })
  valueJson?: Record<string, any>;

  @Column({ name: 'rollout_percent', type: 'int', nullable: true })
  rolloutPercent?: number;

  @Column({ type: 'int', default: 100 })
  priority: number;

  @Column({ name: 'starts_at', type: 'timestamptz', nullable: true })
  startsAt?: Date;

  @Column({ name: 'ends_at', type: 'timestamptz', nullable: true })
  endsAt?: Date;

  @Column({ name: 'deleted_at', type: 'timestamptz', nullable: true })
  deletedAt?: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
