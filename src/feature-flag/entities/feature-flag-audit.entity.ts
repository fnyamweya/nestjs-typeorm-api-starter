import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { FeatureFlag } from './feature-flag.entity';

export enum FeatureFlagAuditAction {
  CREATE = 'CREATE',
  UPDATE = 'UPDATE',
  DELETE = 'DELETE',
}

@Entity('feature_flag_audit')
export class FeatureFlagAudit {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @ManyToOne(() => FeatureFlag, (flag) => flag.audits, {
    nullable: true,
    onDelete: 'SET NULL',
  })
  @JoinColumn({ name: 'feature_flag_id' })
  featureFlag?: FeatureFlag;

  @Column({ name: 'feature_flag_id', type: 'bigint', nullable: true })
  featureFlagId?: string;

  @Column({ type: 'varchar', length: 20 })
  action: FeatureFlagAuditAction;

  @Column({ name: 'actor_id', type: 'varchar', length: 100, nullable: true })
  actorId?: string;

  @Column({ type: 'jsonb', nullable: true })
  snapshot?: Record<string, any>;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}
