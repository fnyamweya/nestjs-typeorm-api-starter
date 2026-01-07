import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';

export type RateLimitArgs = {
  key: string;
  windowSeconds: number;
  max: number;
};

@Injectable()
export class RateLimitService {
  private readonly logger = new Logger(RateLimitService.name);
  private readonly useMemory = process.env.NODE_ENV === 'test';
  private readonly inMemory = new Map<
    string,
    { count: number; expiresAt: number }
  >();

  constructor(private readonly redisService: RedisService) {}

  async assertWithinLimit({
    key,
    windowSeconds,
    max,
  }: RateLimitArgs): Promise<void> {
    const namespacedKey = `ratelimit:${key}`;

    if (this.useMemory) {
      const now = Date.now();
      const entry = this.inMemory.get(namespacedKey);

      if (!entry || entry.expiresAt <= now) {
        this.inMemory.set(namespacedKey, {
          count: 1,
          expiresAt: now + windowSeconds * 1000,
        });
        return;
      }

      entry.count += 1;
      if (entry.count > max) {
        throw new HttpException(
          'Too many requests. Please try again later.',
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }

      this.inMemory.set(namespacedKey, entry);
      return;
    }

    const redis = this.redisService.getClient();

    try {
      const multi = redis.multi();
      multi.incr(namespacedKey);
      multi.ttl(namespacedKey);

      const res = (await multi.exec()) as Array<[Error | null, any]> | null;
      if (!res) {
        // If Redis returned null, be permissive (fail open) rather than blocking auth.
        return;
      }

      const count = Number(res[0]?.[1] ?? 0);
      const ttlSeconds = Number(res[1]?.[1] ?? -1);

      if (ttlSeconds < 0) {
        await redis.expire(namespacedKey, windowSeconds);
      }

      if (count > max) {
        throw new HttpException(
          'Too many requests. Please try again later.',
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }
    } catch (err) {
      // Fail open to avoid auth outages if Redis is down, but log for visibility.
      this.logger.warn(
        `Rate limit check failed (${namespacedKey}): ${err?.message ?? 'unknown error'}`,
      );

      if (
        err instanceof HttpException &&
        err.getStatus() === HttpStatus.TOO_MANY_REQUESTS
      ) {
        throw err;
      }
    }
  }
}
