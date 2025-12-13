import { FeatureFlagStatus, FeatureFlagType } from './entities/feature-flag.entity';
import { FeatureFlagTargetType } from './entities/feature-flag-override.entity';

export interface UserContext {
  userId?: string;
  tenantId?: string;
  roles?: string[];
  env: string;
  attributes?: Record<string, any>;
}

export interface RuntimeOverride {
  id: string;
  targetType: FeatureFlagTargetType;
  targetId?: string;
  env?: string;
  segmentKey?: string;
  valueBoolean?: boolean;
  valueJson?: Record<string, any>;
  rolloutPercent?: number;
  priority: number;
  startsAt?: Date | string;
  endsAt?: Date | string;
}

export interface RuntimeFlag {
  key: string;
  type: FeatureFlagType;
  status: FeatureFlagStatus;
  enabledDefault: boolean;
  overrides: RuntimeOverride[];
}

export interface SegmentDefinitionRule {
  field: string;
  op: 'eq' | 'neq' | 'in' | 'nin';
  value: any;
}

export interface SegmentDefinition {
  rules: SegmentDefinitionRule[];
  operator?: 'AND' | 'OR';
}
