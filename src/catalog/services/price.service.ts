import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Raw, Repository } from 'typeorm';
import { Currency } from '../entities/currency.entity';
import { PriceList } from '../entities/price-list.entity';
import { PriceRow } from '../entities/price-row.entity';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import {
  cacheKeyFromParts,
  cacheKeyHash,
} from 'src/common/cache/cache-key.util';

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
    @InjectRepository(Currency)
    private readonly currencyRepository: Repository<Currency>,
    @InjectRepository(PriceRow)
    private readonly priceRowRepository: Repository<PriceRow>,
    private readonly cache: AppCacheService,
  ) {}

  private formatMinorUnits(amount: string, precision: number) {
    const p = Math.max(0, precision ?? 2);
    const negative = amount.startsWith('-');
    const digits = negative ? amount.slice(1) : amount;
    const padded = digits.padStart(p + 1, '0');
    const intPart = padded.slice(0, padded.length - p);
    const fracPart = padded.slice(padded.length - p);
    const normalizedInt = intPart.replace(/^0+(?=\d)/, '0');
    const value = p === 0 ? normalizedInt : `${normalizedInt}.${fracPart}`;
    return negative ? `-${value}` : value;
  }

  private async getCurrencyPrecision(currencyCode: string) {
    const c = await this.currencyRepository.findOne({
      where: { code: currencyCode },
    });
    return c?.precision ?? 2;
  }

  private async normalizeAndValidateCurrencyCode(
    currencyCode?: string,
  ): Promise<string | undefined> {
    if (!currencyCode) return undefined;
    const normalized = currencyCode.trim().toUpperCase();
    if (!/^[A-Z]{3}$/.test(normalized)) {
      throw new BadRequestException('currencyCode must be a 3-letter ISO code');
    }
    const exists = await this.currencyRepository.exist({
      where: { code: normalized },
    });
    if (!exists) {
      throw new BadRequestException(`Unknown currency code: ${normalized}`);
    }
    return normalized;
  }

  private getCacheKey(opts: {
    productId?: string;
    productSkuId?: string;
    quantity: number;
    priceListId?: string;
    currencyCode?: string;
    context?: PricingContext;
  }) {
    const rawKey = cacheKeyFromParts('price', 'resolve', {
      productId: opts.productId,
      productSkuId: opts.productSkuId,
      quantity: opts.quantity,
      priceListId: opts.priceListId,
      currencyCode: opts.currencyCode,
      context: opts.context ?? null,
    });
    return `price:resolve:${cacheKeyHash(rawKey)}`;
  }

  private getRowConditions(
    selectorJson?: Record<string, unknown>,
  ): PriceConditions | null {
    if (!selectorJson || typeof selectorJson !== 'object') return null;
    // selector_json is expected to be the conditions object (or contain a 'conditions' object).
    const maybe = selectorJson.conditions;
    if (maybe && typeof maybe === 'object') return maybe as PriceConditions;
    return selectorJson as PriceConditions;
  }

  private matchesRowContext(
    selectorJson: Record<string, unknown> | undefined,
    context?: PricingContext,
  ) {
    const conditions = this.getRowConditions(selectorJson);
    if (!conditions) return true;
    if (!context) return false;

    if (conditions.countryCodes?.length) {
      if (
        !context.countryCode ||
        !conditions.countryCodes.includes(context.countryCode)
      )
        return false;
    }
    if (conditions.customerGroupIds?.length) {
      if (
        !context.customerGroupId ||
        !conditions.customerGroupIds.includes(context.customerGroupId)
      )
        return false;
    }
    if (conditions.salesChannelIds?.length) {
      if (
        !context.salesChannelId ||
        !conditions.salesChannelIds.includes(context.salesChannelId)
      )
        return false;
    }
    if (conditions.brandIds?.length) {
      if (!context.brandId || !conditions.brandIds.includes(context.brandId))
        return false;
    }
    if (conditions.tags?.length) {
      const tags = context.tags ?? [];
      const hasAll = conditions.tags.every((tag) => tags.includes(tag));
      if (!hasAll) return false;
    }
    if (
      conditions.attributes &&
      Object.keys(conditions.attributes).length > 0
    ) {
      if (!context.attributes) return false;
      for (const [key, value] of Object.entries(conditions.attributes)) {
        if (context.attributes[key] !== value) return false;
      }
    }

    return true;
  }

  private specificityScoreRow(
    selectorJson: Record<string, unknown> | undefined,
  ) {
    const conditions = this.getRowConditions(selectorJson);
    if (!conditions) return 0;
    let score = 0;
    if (conditions.countryCodes?.length) score += 1;
    if (conditions.customerGroupIds?.length) score += 1;
    if (conditions.salesChannelIds?.length) score += 1;
    if (conditions.brandIds?.length) score += 1;
    if (conditions.tags?.length) score += 1;
    if (conditions.attributes && Object.keys(conditions.attributes).length > 0)
      score += 1;
    return score;
  }

  private selectRowCandidate(candidates: PriceRow[], context?: PricingContext) {
    if (!candidates.length) return null;
    if (!context) return candidates[0];

    let best: PriceRow | null = null;
    let bestScore = -1;
    let bestMin = -1;

    for (const candidate of candidates) {
      if (!this.matchesRowContext(candidate.selectorJson, context)) continue;
      const score = this.specificityScoreRow(candidate.selectorJson);
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

    return best;
  }

  private async selectPriceList(options: {
    priceListId?: string;
    currencyCode?: string;
  }) {
    if (options.priceListId) {
      const p = await this.findPriceListById(options.priceListId);
      if (!p) throw new NotFoundException('Price list not found');
      return p;
    }

    const order = { priority: 'DESC' as const, createdAt: 'DESC' as const };
    if (options.currencyCode) {
      return this.priceListRepository.findOne({
        where: { currency: options.currencyCode, status: 'active' },
        order,
      });
    }

    const any = await this.priceListRepository.findOne({
      where: { status: 'active' },
      order,
    });
    if (any) return any;
    return null;
  }

  async findActivePriceListByCurrency(currencyCode: string) {
    const normalized =
      await this.normalizeAndValidateCurrencyCode(currencyCode);
    if (!normalized) throw new BadRequestException('currencyCode is required');
    return this.priceListRepository.findOne({
      where: { currency: normalized, status: 'active' },
      order: { priority: 'DESC', createdAt: 'DESC' },
    });
  }

  async findPriceListById(id: string) {
    return this.priceListRepository.findOne({ where: { id } });
  }

  async resolveSkuPrice(options: {
    productId?: string;
    productSkuId?: string;
    quantity?: number;
    priceListId?: string;
    currencyCode?: string;
    context?: PricingContext;
  }): Promise<ResolvedPrice> {
    const normalizedCurrencyCode = await this.normalizeAndValidateCurrencyCode(
      options.currencyCode,
    );
    const quantity = options.quantity ?? 1;
    const cacheKey = this.getCacheKey({
      productId: options.productId,
      productSkuId: options.productSkuId,
      quantity,
      priceListId: options.priceListId,
      currencyCode: normalizedCurrencyCode,
      context: options.context,
    });

    return this.cache.remember(
      cacheKey,
      async () => {
        let priceList = await this.selectPriceList({
          priceListId: options.priceListId,
          currencyCode: normalizedCurrencyCode,
        });
        if (!priceList) {
          throw new NotFoundException('No active price list available');
        }

        const precision = await this.getCurrencyPrecision(priceList.currency);

        const now = new Date();
        const attemptFindRows = async (
          pl: PriceList,
          scope: { productId?: string; productSkuId?: string },
        ) => {
          const where: Record<string, unknown> = {
            priceListId: pl.id,
            minQuantity: Raw((alias) => `${alias} <= :q`, { q: quantity }),
            maxQuantity: Raw(
              (alias) => `(${alias} IS NULL OR ${alias} >= :q)`,
              { q: quantity },
            ),
            validFrom: Raw(
              (alias) => `(${alias} IS NULL OR ${alias} <= :now)`,
              { now },
            ),
            validTo: Raw((alias) => `(${alias} IS NULL OR ${alias} >= :now)`, {
              now,
            }),
          };

          if (scope.productSkuId) {
            where.targetType = 'SKU';
            where.targetId = scope.productSkuId;
          }
          if (scope.productId) {
            where.targetType = 'PRODUCT';
            where.targetId = scope.productId;
          }

          const candidates = await this.priceRowRepository.find({
            where,
            order: { minQuantity: 'DESC', createdAt: 'DESC' },
          });

          return this.selectRowCandidate(candidates, options.context);
        };

        let foundRow: PriceRow | null = null;
        if (options.productSkuId) {
          foundRow = await attemptFindRows(priceList, {
            productSkuId: options.productSkuId,
          });
        }
        if (!foundRow && options.productId) {
          foundRow = await attemptFindRows(priceList, {
            productId: options.productId,
          });
        }

        if (!foundRow && !options.priceListId) {
          const others = await this.priceListRepository.find({
            where: { currency: priceList.currency, status: 'active' },
            order: { priority: 'DESC', createdAt: 'DESC' },
          });

          for (const pl of others) {
            if (pl.id === priceList.id) continue;
            if (options.productSkuId) {
              foundRow = await attemptFindRows(pl, {
                productSkuId: options.productSkuId,
              });
            }
            if (!foundRow && options.productId) {
              foundRow = await attemptFindRows(pl, {
                productId: options.productId,
              });
            }
            if (foundRow) {
              priceList = pl;
              break;
            }
          }
        }

        if (!foundRow) {
          throw new NotFoundException('Price for product not found');
        }

        return {
          priceId: foundRow.id,
          priceListId: priceList.id,
          currencyCode: foundRow.currencyCode ?? priceList.currency,
          unitPrice: this.formatMinorUnits(foundRow.unitAmount, precision),
          compareAtPrice: foundRow.compareAtAmount
            ? this.formatMinorUnits(foundRow.compareAtAmount, precision)
            : undefined,
        };
      },
      { ttlSeconds: this.cacheTtlSeconds },
    );
  }
}
