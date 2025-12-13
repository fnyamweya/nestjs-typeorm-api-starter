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
  constructor(
    @InjectRepository(PriceList)
    private readonly priceListRepository: Repository<PriceList>,
    @InjectRepository(ProductVariantPrice)
    private readonly variantPriceRepository: Repository<ProductVariantPrice>,
    @InjectRepository(Currency)
    private readonly currencyRepository: Repository<Currency>,
  ) {}

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
    let priceList: PriceList | null = null;

    if (options.priceListId) {
      priceList = await this.findPriceListById(options.priceListId);
      if (!priceList) {
        throw new NotFoundException('Price list not found');
      }
    } else if (options.currencyCode) {
      priceList = await this.findActivePriceListByCurrency(options.currencyCode);
    } else {
      // If none supplied, pick any active price list
      priceList = (
        await this.priceListRepository.find({ where: { isActive: true }, take: 1 })
      )?.[0];
    }

    if (!priceList) {
      throw new NotFoundException('No active price list available');
    }

    const now = new Date();

    const candidates = await this.variantPriceRepository.find({
      where: {
        priceListId: priceList.id,
        productVariantId: options.productVariantId,
        minQuantity: Raw((alias) => `${alias} <= :q`, { q: quantity }),
        maxQuantity: Raw((alias) => `(${alias} IS NULL OR ${alias} >= :q)`, { q: quantity }),
        validFrom: Raw((alias) => `(${alias} IS NULL OR ${alias} <= :now)`, { now }),
        validTo: Raw((alias) => `(${alias} IS NULL OR ${alias} >= :now)`, { now }),
      },
      order: { minQuantity: 'DESC' },
      take: 1,
    });

    const found = candidates[0];
    if (!found) {
      throw new NotFoundException('Price for variant not found');
    }

    return {
      priceListId: priceList.id,
      currencyCode: priceList.currencyCode,
      unitPrice: found.unitPrice,
      compareAtPrice: found.compareAtPrice,
    };
  }
}
