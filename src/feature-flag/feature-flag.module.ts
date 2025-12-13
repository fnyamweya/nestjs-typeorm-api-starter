import { Global, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { FeatureFlag } from './entities/feature-flag.entity';
import { FeatureFlagOverride } from './entities/feature-flag-override.entity';
import { FeatureSegment } from './entities/feature-segment.entity';
import { FeatureFlagAudit } from './entities/feature-flag-audit.entity';
import { FeatureFlagService } from './feature-flag.service';
import { FeatureFlagGuard } from './feature-flag.guard';

@Global()
@Module({
  imports: [
    ConfigModule,
    TypeOrmModule.forFeature([
      FeatureFlag,
      FeatureFlagOverride,
      FeatureSegment,
      FeatureFlagAudit,
    ]),
  ],
  providers: [FeatureFlagService, { provide: APP_GUARD, useClass: FeatureFlagGuard }],
  exports: [FeatureFlagService],
})
export class FeatureFlagModule {}
