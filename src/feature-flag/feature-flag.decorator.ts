import { SetMetadata } from '@nestjs/common';

export const FEATURE_FLAG_METADATA_KEY = 'feature_flag:key';

export const FeatureFlag = (flagKey: string) =>
  SetMetadata(FEATURE_FLAG_METADATA_KEY, flagKey);
