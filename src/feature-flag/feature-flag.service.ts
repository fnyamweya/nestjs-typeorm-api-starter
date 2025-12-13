import {
  BadRequestException,
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { IsNull, Repository } from 'typeorm';
import Redis, { RedisOptions } from 'ioredis';
import { FeatureFlag, FeatureFlagStatus } from './entities/feature-flag.entity';
import {
  FeatureFlagOverride,
  FeatureFlagTargetType,
} from './entities/feature-flag-override.entity';
import { FeatureSegment } from './entities/feature-segment.entity';
import {
  RuntimeFlag,
  RuntimeOverride,
  SegmentDefinition,
  SegmentDefinitionRule,
  UserContext,
} from './feature-flag.types';

const CACHE_KEY = 'ff:cache:v1';
const CACHE_TTL_SECONDS = 300;

@Injectable()
export class FeatureFlagService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(FeatureFlagService.name);
  private memoryCache = new Map<string, RuntimeFlag>();
  private segmentDefinitions = new Map<string, SegmentDefinition | undefined>();
  private redis?: Redis;
  private redisReady = false;

  constructor(
    @InjectRepository(FeatureFlag)
    private readonly featureFlagRepo: Repository<FeatureFlag>,
    @InjectRepository(FeatureFlagOverride)
    private readonly featureFlagOverrideRepo: Repository<FeatureFlagOverride>,
    @InjectRepository(FeatureSegment)
    private readonly featureSegmentRepo: Repository<FeatureSegment>,
    private readonly configService: ConfigService,
  ) {
    this.redis = this.initializeRedis();
  }

  async onModuleInit() {
    await this.refreshCache();
  }

  async onModuleDestroy() {
    if (this.redis) {
      await this.redis.quit();
    }
  }

  async refreshCache(force = false): Promise<void> {
    if (!force && this.memoryCache.size > 0) return;

    const cached = await this.getCachedFlagsFromRedis();
    if (cached && !force) {
      this.hydrateMemoryCache(cached.flags, cached.segments);
      return;
    }

    const { flags, segments } = await this.loadFromDatabase();
    this.hydrateMemoryCache(flags, segments);
    await this.persistCache(flags, segments);
  }

  async isEnabled(flagKey: string, ctx: UserContext): Promise<boolean> {
    const result = await this.evaluate(flagKey, ctx);
    return result.enabled;
  }

  async getConfigValue<T = Record<string, unknown>>(
    flagKey: string,
    ctx: UserContext,
  ): Promise<T | undefined> {
    const result = await this.evaluate(flagKey, ctx);
    return result.enabled ? (result.config as T | undefined) : undefined;
  }

  async evaluate(
    flagKey: string,
    ctx: UserContext,
  ): Promise<{ enabled: boolean; config?: Record<string, any>; exists: boolean }> {
    await this.refreshCache();

    const flag = this.memoryCache.get(flagKey);
    if (!flag) {
      return { enabled: true, exists: false };
    }

    if (flag.status === FeatureFlagStatus.REMOVED) {
      return { enabled: false, exists: true };
    }

    const applicable = this.findApplicableOverrides(flag, ctx);
    const selected = applicable[0];

    if (!selected) {
      return { enabled: flag.enabledDefault, exists: true };
    }

    const rolloutMatch = this.matchesRollout(selected, ctx);
    if (!rolloutMatch) {
      return { enabled: flag.enabledDefault, exists: true };
    }

    if (selected.valueBoolean !== undefined) {
      return { enabled: selected.valueBoolean, exists: true };
    }

    if (selected.valueJson !== undefined) {
      return { enabled: true, config: selected.valueJson, exists: true };
    }

    if (selected.rolloutPercent !== undefined) {
      return { enabled: true, exists: true };
    }

    return { enabled: flag.enabledDefault, exists: true };
  }

  async forceReload(): Promise<void> {
    await this.refreshCache(true);
  }

  private async loadFromDatabase(): Promise<{
    flags: RuntimeFlag[];
    segments: Map<string, SegmentDefinition | undefined>;
  }> {
    const [flags, overrides, segments] = await Promise.all([
      this.featureFlagRepo.find(),
      this.featureFlagOverrideRepo.find({
        where: { deletedAt: IsNull() },
      }),
      this.featureSegmentRepo.find(),
    ]);

    const segmentMap = new Map<string, SegmentDefinition | undefined>();
    const segmentKeyById = new Map<string, string>();
    for (const segment of segments) {
      segmentMap.set(
        segment.key,
        segment.definition as SegmentDefinition | undefined,
      );
      segmentKeyById.set(segment.id, segment.key);
    }

    const overridesByFlag = overrides.reduce<Record<string, RuntimeOverride[]>>(
      (acc, override) => {
        const key = override.featureFlagId;
        if (!acc[key]) acc[key] = [];
        acc[key].push({
          id: override.id,
          targetType: override.targetType,
          targetId: this.normalizeTargetId(override),
          env: override.env?.toLowerCase(),
          segmentKey: override.segmentId
            ? segmentKeyById.get(override.segmentId) || undefined
            : undefined,
          valueBoolean: override.valueBoolean,
          valueJson: override.valueJson as any,
          rolloutPercent: override.rolloutPercent ?? undefined,
          priority: override.priority,
          startsAt: override.startsAt,
          endsAt: override.endsAt,
        });
        return acc;
      },
      {},
    );

    const runtimeFlags: RuntimeFlag[] = flags.map((flag) => ({
      key: flag.key,
      type: flag.type,
      status: flag.status,
      enabledDefault: flag.enabledDefault,
      overrides: overridesByFlag[flag.id] || [],
    }));

    return { flags: runtimeFlags, segments: segmentMap };
  }

  private hydrateMemoryCache(
    flags: RuntimeFlag[],
    segments: Map<string, SegmentDefinition | undefined>,
  ) {
    this.memoryCache = new Map(flags.map((flag) => [flag.key, flag]));
    this.segmentDefinitions = segments;
  }

  private async persistCache(
    flags: RuntimeFlag[],
    segments: Map<string, SegmentDefinition | undefined>,
  ) {
    if (!this.isRedisAvailable()) return;

    try {
      const payload = {
        flags,
        segments: Array.from(segments.entries()),
      };
      await this.redis?.set(CACHE_KEY, JSON.stringify(payload), 'EX', CACHE_TTL_SECONDS);
    } catch (err) {
      this.logger.warn(`Failed to write feature flag cache to Redis: ${err?.message}`);
    }
  }

  private async getCachedFlagsFromRedis(): Promise<
    | { flags: RuntimeFlag[]; segments: Map<string, SegmentDefinition | undefined> }
    | null
  > {
    if (!this.isRedisAvailable()) return null;

    try {
      const payload = await this.redis?.get(CACHE_KEY);
      if (!payload) return null;
      const parsed = JSON.parse(payload) as {
        flags: RuntimeFlag[];
        segments: [string, SegmentDefinition | undefined][];
      };
      return {
        flags: parsed.flags,
        segments: new Map(parsed.segments),
      };
    } catch (err) {
      this.logger.warn(`Failed to read feature flag cache from Redis: ${err?.message}`);
      return null;
    }
  }

  private findApplicableOverrides(
    flag: RuntimeFlag,
    ctx: UserContext,
  ): RuntimeOverride[] {
    const now = new Date();
    const roles = (ctx.roles || []).map((r) => r.toLowerCase());
    const env = (ctx.env || '').toLowerCase();

    const matches = flag.overrides.filter((o) => {
      if (o.startsAt && new Date(o.startsAt) > now) return false;
      if (o.endsAt && new Date(o.endsAt) < now) return false;
      if (o.env && o.env !== env) return false;

      if (o.segmentKey) {
        const definition = this.segmentDefinitions.get(o.segmentKey);
        if (!this.evaluateSegment(definition, ctx.attributes || {})) return false;
      }

      switch (o.targetType) {
        case FeatureFlagTargetType.USER:
          return !!ctx.userId && ctx.userId === o.targetId;
        case FeatureFlagTargetType.ROLE:
          return roles.includes(o.targetId || '');
        case FeatureFlagTargetType.TENANT:
          return !!ctx.tenantId && ctx.tenantId === o.targetId;
        case FeatureFlagTargetType.ENV:
          return !!env && (!!o.targetId ? env === (o.targetId || '').toLowerCase() : true);
        default:
          return false;
      }
    });

    return matches.sort((a, b) => a.priority - b.priority);
  }

  private matchesRollout(override: RuntimeOverride, ctx: UserContext): boolean {
    if (override.rolloutPercent === undefined) return true;
    const seed = ctx.userId || ctx.tenantId || 'anonymous';
    const bucket = this.stableHash(seed) % 100;
    return bucket < override.rolloutPercent;
  }

  private evaluateSegment(
    definition: SegmentDefinition | undefined,
    attributes: Record<string, any>,
  ): boolean {
    if (!definition || !definition.rules || definition.rules.length === 0) return true;
    const op = definition.operator || 'AND';

    const evalRule = (rule: SegmentDefinitionRule): boolean => {
      const value = attributes[rule.field];
      switch (rule.op) {
        case 'eq':
          return value === rule.value;
        case 'neq':
          return value !== rule.value;
        case 'in':
          return Array.isArray(rule.value) && rule.value.includes(value);
        case 'nin':
          return Array.isArray(rule.value) && !rule.value.includes(value);
        default:
          return false;
      }
    };

    const results = definition.rules.map(evalRule);
    return op === 'AND' ? results.every(Boolean) : results.some(Boolean);
  }

  private buildRedisOptions(): RedisOptions {
    const host = this.configService.get<string>('REDIS_HOST', '127.0.0.1');
    const port = Number(this.configService.get<string>('REDIS_PORT', '6379'));
    const password = this.configService.get<string>('REDIS_PASSWORD');
    const username = this.configService.get<string>('REDIS_USERNAME');
    const db = Number(this.configService.get<string>('REDIS_DB', '0'));
    const tlsEnabled = this.configService.get<string>('REDIS_TLS', 'false') === 'true';

    const options: RedisOptions = {
      host,
      port,
      db,
      maxRetriesPerRequest: null,
    };

    if (password) options.password = password;
    if (username) options.username = username;
    if (tlsEnabled) options.tls = {};
    return options;
  }

  private initializeRedis(): Redis | undefined {
    const options = this.buildRedisOptions();
    try {
      const client = new Redis(options);

      client.on('connect', () => {
        this.redisReady = true;
      });

      client.on('error', (err) => {
        this.redisReady = false;
        this.logger.warn(
          `Redis unavailable, using in-memory cache only: ${err?.message}`,
        );
      });

      return client;
    } catch (err) {
      this.redisReady = false;
      this.logger.warn(
        `Redis initialization failed, using in-memory cache only: ${err?.message}`,
      );
      return undefined;
    }
  }

  private isRedisAvailable(): boolean {
    return !!this.redis && this.redisReady;
  }

  private normalizeTargetId(override: FeatureFlagOverride): string | undefined {
    if (!override.targetId) return undefined;
    if (
      override.targetType === FeatureFlagTargetType.ROLE ||
      override.targetType === FeatureFlagTargetType.ENV
    ) {
      return override.targetId.toLowerCase();
    }
    return override.targetId;
  }

  private stableHash(input: string): number {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
      hash = (hash * 31 + input.charCodeAt(i)) | 0;
    }
    return Math.abs(hash);
  }

  // Helper for seeding/testing to register simple boolean flags quickly
  async upsertBooleanFlag(
    key: string,
    enabled: boolean,
    actorId?: string,
  ) {
    if (!key) {
      throw new BadRequestException('Flag key is required');
    }

    const existing = await this.featureFlagRepo.findOne({ where: { key } });
    if (existing) {
      existing.enabledDefault = enabled;
      await this.featureFlagRepo.save(existing);
    } else {
      const created = this.featureFlagRepo.create({
        key,
        name: key,
        enabledDefault: enabled,
      });
      await this.featureFlagRepo.save(created);
    }

    await this.refreshCache(true);
    void actorId; // reserved for future audit
  }
}
