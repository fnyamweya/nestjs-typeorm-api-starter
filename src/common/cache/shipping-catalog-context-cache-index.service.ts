import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';

type CatalogContextIndexable = {
  productIds?: string[];
  categoryIds?: string[];
  taxonomyIds?: string[];
};

@Injectable()
export class ShippingCatalogContextCacheIndexService {
  private readonly logger = new Logger(
    ShippingCatalogContextCacheIndexService.name,
  );
  private readonly idxPrefix = 'shipping:catalog-context:idx:';

  constructor(private readonly redisService: RedisService) {}

  private productIndexKey(productId: string): string {
    return `${this.idxPrefix}product:${String(productId)}`;
  }

  private categoryIndexKey(categoryId: string): string {
    return `${this.idxPrefix}category:${String(categoryId)}`;
  }

  private taxonomyIndexKey(taxonomyId: string): string {
    return `${this.idxPrefix}taxonomy:${String(taxonomyId)}`;
  }

  async indexCacheKey(
    cacheKey: string,
    ctx: CatalogContextIndexable,
    ttlSeconds: number,
  ): Promise<void> {
    const redis = this.redisService.getClient();

    const productIds = Array.from(new Set((ctx.productIds ?? []).map(String)));
    const categoryIds = Array.from(
      new Set((ctx.categoryIds ?? []).map(String)),
    );
    const taxonomyIds = Array.from(
      new Set((ctx.taxonomyIds ?? []).map(String)),
    );

    const indexKeys = [
      ...productIds.map((id) => this.productIndexKey(id)),
      ...categoryIds.map((id) => this.categoryIndexKey(id)),
      ...taxonomyIds.map((id) => this.taxonomyIndexKey(id)),
    ];

    if (!indexKeys.length) return;

    // Keep the index around longer than the cache entry to support targeted invalidation.
    const indexTtlSeconds = Math.max(3600, ttlSeconds * 4);

    try {
      const pipeline = redis.pipeline();
      for (const idxKey of indexKeys) {
        pipeline.sadd(idxKey, cacheKey);
        pipeline.expire(idxKey, indexTtlSeconds);
      }
      await pipeline.exec();
    } catch (err: any) {
      this.logger.debug(
        `Index write failed (${cacheKey}): ${err?.message ?? 'unknown error'}`,
      );
    }
  }

  async invalidateByProductIds(productIds: string[]): Promise<void> {
    const keys = Array.from(new Set(productIds.map(String))).map((id) =>
      this.productIndexKey(id),
    );
    await this.invalidateByIndexKeys(keys);
  }

  async invalidateByCategoryIds(categoryIds: string[]): Promise<void> {
    const keys = Array.from(new Set(categoryIds.map(String))).map((id) =>
      this.categoryIndexKey(id),
    );
    await this.invalidateByIndexKeys(keys);
  }

  async invalidateByTaxonomyIds(taxonomyIds: string[]): Promise<void> {
    const keys = Array.from(new Set(taxonomyIds.map(String))).map((id) =>
      this.taxonomyIndexKey(id),
    );
    await this.invalidateByIndexKeys(keys);
  }

  private async invalidateByIndexKeys(indexKeys: string[]): Promise<void> {
    if (!indexKeys.length) return;

    const redis = this.redisService.getClient();

    try {
      const pipeline = redis.pipeline();
      for (const idxKey of indexKeys) pipeline.smembers(idxKey);
      const results = await pipeline.exec();

      const cacheKeys = new Set<string>();
      for (const [err, members] of results ?? []) {
        if (err) continue;
        for (const k of (members as string[]) ?? []) cacheKeys.add(String(k));
      }

      const cacheKeyList = Array.from(cacheKeys);
      if (cacheKeyList.length) {
        for (let i = 0; i < cacheKeyList.length; i += 500) {
          await redis.del(...cacheKeyList.slice(i, i + 500));
        }
      }

      for (let i = 0; i < indexKeys.length; i += 500) {
        await redis.del(...indexKeys.slice(i, i + 500));
      }
    } catch (err: any) {
      this.logger.debug(
        `Index invalidate failed (${indexKeys[0]}): ${err?.message ?? 'unknown error'}`,
      );
    }
  }
}
