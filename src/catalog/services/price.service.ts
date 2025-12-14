import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Raw, Repository } from 'typeorm';
import { PriceList } from '../entities/price-list.entity';
import { ProductVariantPrice } from '../entities/product-variant-price.entity';
import { Currency } from '../entities/currency.entity';

export interface ResolvedPrice {
  priceListId: string;
  currencyCode: string;
  unitPrice: string;
  compareAtPrice?: string;
}

@Injectable()
export class PriceService {
  private cache = new Map<string, { value: ResolvedPrice; expiresAt: number }>();
  private cacheTtlMs = 10000; // 10s default TTL for simple in-memory cache
  constructor(
    @InjectRepository(PriceList)
    private readonly priceListRepository: Repository<PriceList>,
    @InjectRepository(ProductVariantPrice)
    private readonly variantPriceRepository: Repository<ProductVariantPrice>,
    @InjectRepository(Currency)
    private readonly currencyRepository: Repository<Currency>,
  ) {}

  private getCacheKey(opts: { productVariantId: string; quantity: number; priceListId?: string; currencyCode?: string }) {
    return `variant:${opts.productVariantId}:q:${opts.quantity}:pl:${opts.priceListId ?? 'none'}:c:${opts.currencyCode ?? 'none'}`;
  }

  private getFromCache(key: string) {
    const e = this.cache.get(key);
    if (!e) return null;
    if (Date.now() > e.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    return e.value;
  }

  private setCache(key: string, value: ResolvedPrice) {
    this.cache.set(key, { value, expiresAt: Date.now() + this.cacheTtlMs });
  }

  /**
   * Selects an appropriate price list given options using a precedence strategy:
   * 1. explicit priceListId
   * 2. active price lists for given currency ordered by metaJson.priority then valid_from
   * 3. any active price list
   */
  private async selectPriceList(options: { priceListId?: string; currencyCode?: string }) {
    if (options.priceListId) {
      const p = await this.findPriceListById(options.priceListId);
      if (!p) throw new NotFoundException('Price list not found');
      return p;
    }

    const now = new Date();

    if (options.currencyCode) {
      // Fetch active price lists for currency and prefer higher priority (metaJson.priority)
      const lists = await this.priceListRepository.find({ where: { currencyCode: options.currencyCode, isActive: true } });
      if (lists && lists.length > 0) {
        lists.sort((a, b) => {
          const pa = (a.metaJson as any)?.priority ?? 0;
          const pb = (b.metaJson as any)?.priority ?? 0;
          if (pb === pa) {
            // prefer newer valid_from
            const da = a.validFrom ? new Date(a.validFrom).getTime() : 0;
            const db = b.validFrom ? new Date(b.validFrom).getTime() : 0;
            return db - da;
          }
          return pb - pa;
        });
        // pick first valid one by window
        const chosen = lists.find((l) => {
          if (l.validFrom && l.validFrom > now) return false;
          if (l.validTo && l.validTo < now) return false;
          return true;
        });
        if (chosen) return chosen;
        // otherwise return first active list
        return lists[0];
      }
    }

    // fallback to any active price list
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
    productVariantId: string;
    quantity?: number;
    priceListId?: string;
    currencyCode?: string;
  }): Promise<ResolvedPrice> {
    const quantity = options.quantity ?? 1;
    const cacheKey = this.getCacheKey({ productVariantId: options.productVariantId, quantity, priceListId: options.priceListId, currencyCode: options.currencyCode });
    const cached = this.getFromCache(cacheKey);
    if (cached) return cached;

    let priceList = await this.selectPriceList({ priceListId: options.priceListId, currencyCode: options.currencyCode });
    if (!priceList) {
      throw new NotFoundException('No active price list available');
    }

    const now = new Date();

    // try primary price list and if not found, try other price lists for same currency
    const attemptFind = async (pl: PriceList) => {
      const candidates = await this.variantPriceRepository.find({
        where: {
          priceListId: pl.id,
          productVariantId: options.productVariantId,
          minQuantity: Raw((alias) => `${alias} <= :q`, { q: quantity }),
          maxQuantity: Raw((alias) => `(${alias} IS NULL OR ${alias} >= :q)`, { q: quantity }),
          validFrom: Raw((alias) => `(${alias} IS NULL OR ${alias} <= :now)`, { now }),
          validTo: Raw((alias) => `(${alias} IS NULL OR ${alias} >= :now)`, { now }),
        },
        order: { minQuantity: 'DESC' },
        take: 1,
      });
      return candidates[0];
    };

    let found = await attemptFind(priceList);

    if (!found && !options.priceListId) {
      // fallback: look through other active price lists with same currency (ordered by precedence)
      const others = await this.priceListRepository.find({ where: { currencyCode: priceList.currencyCode, isActive: true } });
      // ensure precedence ordering like selectPriceList
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
        found = await attemptFind(pl);
        if (found) {
          priceList = pl;
          break;
        }
      }
    }

    if (!found) {
      throw new NotFoundException('Price for variant not found');
    }

    const resolved: ResolvedPrice = {
      priceListId: priceList.id,
      currencyCode: priceList.currencyCode,
      unitPrice: found.unitPrice,
      compareAtPrice: found.compareAtPrice,
    };

    this.setCache(cacheKey, resolved);

    return resolved;
  }
}
