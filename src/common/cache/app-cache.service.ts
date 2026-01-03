import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';

export type CacheRememberOptions = {
  ttlSeconds: number;
};

@Injectable()
export class AppCacheService {
  private readonly logger = new Logger(AppCacheService.name);

  constructor(private readonly redisService: RedisService) {}

  async get<T>(key: string): Promise<T | null> {
    try {
      const redis = this.redisService.getClient();
      const value = await redis.get(key);
      if (!value) return null;
      return JSON.parse(value) as T;
    } catch (err: any) {
      this.logger.debug(`Cache get failed (${key}): ${err?.message ?? 'unknown error'}`);
      return null;
    }
  }

  async set<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
    try {
      const redis = this.redisService.getClient();
      await redis.set(key, JSON.stringify(value), 'EX', ttlSeconds);
    } catch (err: any) {
      this.logger.debug(`Cache set failed (${key}): ${err?.message ?? 'unknown error'}`);
    }
  }

  async del(key: string): Promise<void> {
    try {
      const redis = this.redisService.getClient();
      await redis.del(key);
    } catch (err: any) {
      this.logger.debug(`Cache del failed (${key}): ${err?.message ?? 'unknown error'}`);
    }
  }

  async delByPrefix(prefix: string): Promise<void> {
    const redis = this.redisService.getClient();
    const pattern = `${prefix}*`;

    try {
      let cursor = '0';

      do {
        const [nextCursor, keys] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 200);
        cursor = nextCursor;

        if (keys.length) {
          await redis.del(...keys);
        }
      } while (cursor !== '0');
    } catch (err: any) {
      this.logger.debug(
        `Cache delByPrefix failed (${prefix}): ${err?.message ?? 'unknown error'}`,
      );
    }
  }

  async remember<T>(key: string, factory: () => Promise<T>, options: CacheRememberOptions): Promise<T> {
    const cached = await this.get<T>(key);
    if (cached !== null) return cached;

    const value = await factory();
    await this.set(key, value, options.ttlSeconds);
    return value;
  }
}
