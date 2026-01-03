import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Raw, Repository } from 'typeorm';
import { PriceList } from '../entities/price-list.entity';
import { ProductPrice } from '../entities/product-price.entity';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { cacheKeyFromParts, cacheKeyHash } from 'src/common/cache/cache-key.util';

export interface ResolvedPrice {
  priceId: string;
  priceListId: string;
  currencyCode: string;
  unitPrice: string;
  compareAtPrice?: string;
}

export interface PricingContext {
  countryCode?: string;
  customerGroupId?: string;
  salesChannelId?: string;
  brandId?: string;
  tags?: string[];
  attributes?: Record<string, string | number | boolean>;
}

interface PriceConditions {
  countryCodes?: string[];
  customerGroupIds?: string[];
  salesChannelIds?: string[];
  brandIds?: string[];
  tags?: string[];
  attributes?: Record<string, string | number | boolean>;
}

@Injectable()
export class PriceService {
  private cacheTtlSeconds = 10;

  constructor(
    @InjectRepository(PriceList)
    private readonly priceListRepository: Repository<PriceList>,
    @InjectRepository(ProductPrice)
    private readonly productPriceRepository: Repository<ProductPrice>,
    private readonly cache: AppCacheService,
  ) {}

  private getCacheKey(opts: {
    productId?: string;
    productVariantId?: string;
    quantity: number;
    priceListId?: string;
    currencyCode?: string;
    context?: PricingContext;
  }) {
    const rawKey = cacheKeyFromParts('price', 'resolve', {
      productId: opts.productId,
      productVariantId: opts.productVariantId,
      quantity: opts.quantity,
      priceListId: opts.priceListId,
      currencyCode: opts.currencyCode,
      context: opts.context ?? null,
    });
    return `price:resolve:${cacheKeyHash(rawKey)}`;
  }

  private getConditions(metaJson?: Record<string, unknown>): PriceConditions | null {
    if (!metaJson || typeof metaJson !== 'object') return null;
    const raw = (metaJson as Record<string, unknown>).conditions;
    if (!raw || typeof raw !== 'object') return null;
    return raw as PriceConditions;
  }

  private matchesContext(metaJson: Record<string, unknown> | undefined, context?: PricingContext) {
    const conditions = this.getConditions(metaJson);
    if (!conditions) return true;
    if (!context) return false;

    if (conditions.countryCodes?.length) {
      if (!context.countryCode || !conditions.countryCodes.includes(context.countryCode)) return false;
    }
    if (conditions.customerGroupIds?.length) {
      if (!context.customerGroupId || !conditions.customerGroupIds.includes(context.customerGroupId)) return false;
    }
    if (conditions.salesChannelIds?.length) {
      if (!context.salesChannelId || !conditions.salesChannelIds.includes(context.salesChannelId)) return false;
    }
    if (conditions.brandIds?.length) {
      if (!context.brandId || !conditions.brandIds.includes(context.brandId)) return false;
    }
    if (conditions.tags?.length) {
      const tags = context.tags ?? [];
      const hasAll = conditions.tags.every((tag) => tags.includes(tag));
      if (!hasAll) return false;
    }
    if (conditions.attributes && Object.keys(conditions.attributes).length > 0) {
      if (!context.attributes) return false;
      for (const [key, value] of Object.entries(conditions.attributes)) {
        if (context.attributes[key] !== value) return false;
      }
    }

    return true;
  }

  private isUnconditional(metaJson: Record<string, unknown> | undefined) {
    const conditions = this.getConditions(metaJson);
    if (!conditions) return true;
    return Object.keys(conditions).length === 0;
  }

  private specificityScore(metaJson: Record<string, unknown> | undefined) {
    const conditions = this.getConditions(metaJson);
    if (!conditions) return 0;
    let score = 0;
    if (conditions.countryCodes?.length) score += 1;
    if (conditions.customerGroupIds?.length) score += 1;
    if (conditions.salesChannelIds?.length) score += 1;
    if (conditions.brandIds?.length) score += 1;
    if (conditions.tags?.length) score += 1;
    if (conditions.attributes && Object.keys(conditions.attributes).length > 0) score += 1;
    return score;
  }

  private selectCandidate(candidates: ProductPrice[], context?: PricingContext) {
    if (!candidates.length) return null;
    if (!context) return candidates[0];

    let best: ProductPrice | null = null;
    let bestScore = -1;
    let bestMin = -1;

    for (const candidate of candidates) {
      if (!this.matchesContext(candidate.metaJson, context)) continue;
      const score = this.specificityScore(candidate.metaJson);
      if (!best) {
        best = candidate;
        bestScore = score;
        bestMin = candidate.minQuantity;
        continue;
      }
      if (candidate.minQuantity > bestMin) {
        best = candidate;
        bestScore = score;
        bestMin = candidate.minQuantity;
        continue;
      }
      if (candidate.minQuantity === bestMin && score > bestScore) {
        best = candidate;
        bestScore = score;
      }
    }

    if (best) return best;

    const fallback = candidates.find((candidate) => this.isUnconditional(candidate.metaJson));
    return fallback ?? null;
  }

  private async selectPriceList(options: { priceListId?: string; currencyCode?: string }) {
    if (options.priceListId) {
      const p = await this.findPriceListById(options.priceListId);
      if (!p) throw new NotFoundException('Price list not found');
      return p;
    }

    const now = new Date();

    if (options.currencyCode) {
      const lists = await this.priceListRepository.find({ where: { currencyCode: options.currencyCode, isActive: true } });
      if (lists && lists.length > 0) {
        lists.sort((a, b) => {
          const pa = (a.metaJson as any)?.priority ?? 0;
          const pb = (b.metaJson as any)?.priority ?? 0;
          if (pb === pa) {
            const da = a.validFrom ? new Date(a.validFrom).getTime() : 0;
            const db = b.validFrom ? new Date(b.validFrom).getTime() : 0;
            return db - da;
          }
          return pb - pa;
        });
        const chosen = lists.find((l) => {
          if (l.validFrom && l.validFrom > now) return false;
          if (l.validTo && l.validTo < now) return false;
          return true;
        });
        if (chosen) return chosen;
        return lists[0];
      }
    }

    const any = (await this.priceListRepository.find({ where: { isActive: true }, take: 1 }))?.[0];
    if (any) return any;
    return null;
  }

  async findActivePriceListByCurrency(currencyCode: string) {
    return this.priceListRepository.findOne({ where: { currencyCode, isActive: true } });
  }

  async findPriceListById(id: string) {
    return this.priceListRepository.findOne({ where: { id } });
  }

  async resolveVariantPrice(options: {
    productId?: string;
    productVariantId?: string;
    quantity?: number;
    priceListId?: string;
    currencyCode?: string;
    context?: PricingContext;
  }): Promise<ResolvedPrice> {
    const quantity = options.quantity ?? 1;
    const cacheKey = this.getCacheKey({
      productId: options.productId,
      productVariantId: options.productVariantId,
      quantity,
      priceListId: options.priceListId,
      currencyCode: options.currencyCode,
      context: options.context,
    });

    return this.cache.remember(
      cacheKey,
      async () => {
        let priceList = await this.selectPriceList({ priceListId: options.priceListId, currencyCode: options.currencyCode });
        if (!priceList) {
          throw new NotFoundException('No active price list available');
        }

        const now = new Date();
        const attemptFind = async (pl: PriceList, scope: { productId?: string; productVariantId?: string }) => {
          const where: Record<string, unknown> = {
            priceListId: pl.id,
            minQuantity: Raw((alias) => `${alias} <= :q`, { q: quantity }),
            maxQuantity: Raw((alias) => `(${alias} IS NULL OR ${alias} >= :q)`, { q: quantity }),
            validFrom: Raw((alias) => `(${alias} IS NULL OR ${alias} <= :now)`, { now }),
            validTo: Raw((alias) => `(${alias} IS NULL OR ${alias} >= :now)`, { now }),
          };

          if (scope.productVariantId) {
            where.productVariantId = scope.productVariantId;
          }
          if (scope.productId) {
            where.productId = scope.productId;
          }

          const candidates = await this.productPriceRepository.find({
            where,
            order: { minQuantity: 'DESC', createdAt: 'DESC' },
          });

          return this.selectCandidate(candidates, options.context);
        };

        let found: ProductPrice | null = null;
        if (options.productVariantId) {
          found = await attemptFind(priceList, { productVariantId: options.productVariantId });
        }
        if (!found && options.productId) {
          found = await attemptFind(priceList, { productId: options.productId });
        }

        if (!found && !options.priceListId) {
          const others = await this.priceListRepository.find({ where: { currencyCode: priceList.currencyCode, isActive: true } });
          others.sort((a, b) => {
            const pa = (a.metaJson as any)?.priority ?? 0;
            const pb = (b.metaJson as any)?.priority ?? 0;
            if (pb === pa) {
              const da = a.validFrom ? new Date(a.validFrom).getTime() : 0;
              const db = b.validFrom ? new Date(b.validFrom).getTime() : 0;
              return db - da;
            }
            return pb - pa;
          });

          for (const pl of others) {
            if (pl.id === priceList.id) continue;
            if (options.productVariantId) {
              found = await attemptFind(pl, { productVariantId: options.productVariantId });
            }
            if (!found && options.productId) {
              found = await attemptFind(pl, { productId: options.productId });
            }
            if (found) {
              priceList = pl;
              break;
            }
          }
        }

        if (!found) {
          throw new NotFoundException('Price for product not found');
        }

        return {
          priceId: found.id,
          priceListId: priceList.id,
          currencyCode: priceList.currencyCode,
          unitPrice: found.unitPrice,
          compareAtPrice: found.compareAtPrice,
        };
      },
      { ttlSeconds: this.cacheTtlSeconds },
    );
  }
}
