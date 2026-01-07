import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ProductSku } from '../../catalog/entities/product-sku.entity';
import { PriceService } from '../../catalog/services/price.service';
import { ShippingMatrixService } from './shipping-matrix.service';
import { CatalogShippingContextService } from './catalog-shipping-context.service';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import {
  cacheKeyFromParts,
  cacheKeyHash,
} from 'src/common/cache/cache-key.util';
import { Location } from '../../location/entities/location.entity';
import { CurrencyService } from 'src/currency/currency.service';

@Injectable()
export class ShippingQuotesService {
  constructor(
    @InjectRepository(ProductSku)
    private readonly productSkuRepository: Repository<ProductSku>,
    @InjectRepository(Location)
    private readonly locationRepository: Repository<Location>,
    private readonly priceService: PriceService,
    private readonly shippingMatrixService: ShippingMatrixService,
    private readonly catalogShippingContextService: CatalogShippingContextService,
    private readonly cache: AppCacheService,
    private readonly currencyService: CurrencyService,
  ) {}

  async getQuotes(payload: {
    shippingLocationId: string;
    orderItems: Array<{ productSkuId: string; quantity: number }>;
    priceListId?: string;
    currencyCode?: string;
    salesChannelCode?: string;
  }) {
    const currencyCode = payload.currencyCode
      ? await this.currencyService.assertExists(payload.currencyCode)
      : await this.currencyService.getDefaultCurrencyCode();

    const normalizedItems = (payload.orderItems ?? [])
      .map((i) => ({
        productSkuId: String(i.productSkuId),
        quantity: Number(i.quantity ?? 0),
      }))
      .filter((i) => i.productSkuId && i.quantity > 0)
      .sort((a, b) => a.productSkuId.localeCompare(b.productSkuId));

    const rawKey = cacheKeyFromParts('shipping', 'quotes', {
      shippingLocationId: payload.shippingLocationId,
      priceListId: payload.priceListId,
      currencyCode,
      salesChannelCode: payload.salesChannelCode,
      items: normalizedItems,
    });
    const key = `shipping:quotes:${cacheKeyHash(rawKey)}`;

    return this.cache.remember(
      key,
      () =>
        this.computeQuotes({
          shippingLocationId: payload.shippingLocationId,
          orderItems: normalizedItems,
          priceListId: payload.priceListId,
          currencyCode,
          salesChannelCode: payload.salesChannelCode,
        }),
      { ttlSeconds: 30 },
    );
  }

  private async computeQuotes(payload: {
    shippingLocationId: string;
    orderItems: Array<{ productSkuId: string; quantity: number }>;
    priceListId?: string;
    currencyCode?: string;
    salesChannelCode?: string;
  }) {
    const countryCode = (
      await this.locationRepository.findOne({
        where: { id: payload.shippingLocationId },
        select: { id: true, countryCode: true },
      })
    )?.countryCode;

    const productIds = new Set<string>();
    let itemsSubtotal = 0;
    let totalItemCount = 0;
    let totalWeight = 0;
    let anyRequiresShipping = false;

    for (const item of payload.orderItems) {
      const sku = await this.productSkuRepository.findOne({
        where: { id: item.productSkuId },
      });
      if (!sku) throw new NotFoundException('Product SKU not found');

      productIds.add(sku.productId);
      totalItemCount += item.quantity;

      anyRequiresShipping =
        anyRequiresShipping || Boolean(sku.requiresShipping);

      // subtotal via PriceService
      const resolved = await this.priceService.resolveSkuPrice({
        productSkuId: sku.id,
        productId: sku.productId,
        priceListId: payload.priceListId,
        currencyCode: payload.currencyCode,
        quantity: item.quantity,
        context: countryCode ? { countryCode } : undefined,
      });

      const unitPrice = parseFloat(resolved.unitPrice);
      itemsSubtotal += unitPrice * item.quantity;

      // weight (best effort)
      const weight = Number(
        (sku as any).attributes?.weight ?? (sku as any).weight ?? 0,
      );
      totalWeight += (weight || 0) * item.quantity;
    }

    if (!anyRequiresShipping) return [];

    const currencyCode =
      payload.currencyCode ??
      (await this.currencyService.getDefaultCurrencyCode());

    const catalogShipping =
      await this.catalogShippingContextService.resolveCatalogShippingContext(
        Array.from(productIds),
      );

    const quotes = await this.shippingMatrixService.getQuotes({
      locationId: payload.shippingLocationId,
      subtotal: itemsSubtotal,
      totalWeight,
      itemCount: totalItemCount,
      currencyCode,
      channelCode: payload.salesChannelCode,
      allowedMethodCodes: catalogShipping.allowedMethodCodes,
      excludedMethodCodes: catalogShipping.excludedMethodCodes,
      ratePriorityBoost: catalogShipping.ratePriorityBoost,
      productIds: catalogShipping.productIds,
      categoryIds: catalogShipping.categoryIds,
      taxonomyIds: catalogShipping.taxonomyIds,
    });

    return quotes.map((q) => ({
      amount: q.amount,
      currencyCode,
      method: {
        id: q.method.id,
        code: q.method.code,
        displayName: q.method.displayName,
      },
      rate: {
        id: q.rate.id,
        calculationType: q.rate.calculationType,
        priority: q.rate.priority,
        price: q.rate.price,
        pricePerUnit: q.rate.pricePerUnit,
        minWeight: q.rate.minWeight,
        maxWeight: q.rate.maxWeight,
        minSubtotal: q.rate.minSubtotal,
        maxSubtotal: q.rate.maxSubtotal,
        currencyCode: q.rate.currencyCode ?? currencyCode,
        metaJson: q.rate.metaJson,
      },
      effectivePriority: q.effectivePriority,
    }));
  }
}
