import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ProductVariant } from '../../catalog/entities/product-variant.entity';
import { PriceService } from '../../catalog/services/price.service';
import { ShippingMatrixService } from './shipping-matrix.service';
import { CatalogShippingContextService } from './catalog-shipping-context.service';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { cacheKeyFromParts, cacheKeyHash } from 'src/common/cache/cache-key.util';

@Injectable()
export class ShippingQuotesService {
  constructor(
    @InjectRepository(ProductVariant)
    private readonly productVariantRepository: Repository<ProductVariant>,
    private readonly priceService: PriceService,
    private readonly shippingMatrixService: ShippingMatrixService,
    private readonly catalogShippingContextService: CatalogShippingContextService,
    private readonly cache: AppCacheService,
  ) {}

  async getQuotes(payload: {
    shippingLocationId: string;
    orderItems: Array<{ productVariantId: string; quantity: number }>;
    priceListId?: string;
    currencyCode?: string;
  }) {
    const normalizedItems = (payload.orderItems ?? [])
      .map((i) => ({
        productVariantId: String(i.productVariantId),
        quantity: Number(i.quantity ?? 0),
      }))
      .filter((i) => i.productVariantId && i.quantity > 0)
      .sort((a, b) => a.productVariantId.localeCompare(b.productVariantId));

    const rawKey = cacheKeyFromParts('shipping', 'quotes', {
      shippingLocationId: payload.shippingLocationId,
      priceListId: payload.priceListId,
      currencyCode: payload.currencyCode ?? 'KES',
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
          currencyCode: payload.currencyCode,
        }),
      { ttlSeconds: 30 },
    );
  }

  private async computeQuotes(payload: {
    shippingLocationId: string;
    orderItems: Array<{ productVariantId: string; quantity: number }>;
    priceListId?: string;
    currencyCode?: string;
  }) {
    const productIds = new Set<string>();
    let itemsSubtotal = 0;
    let totalItemCount = 0;
    let totalWeight = 0;
    let anyRequiresShipping = false;

    for (const item of payload.orderItems) {
      const variant = await this.productVariantRepository.findOne({ where: { id: item.productVariantId } });
      if (!variant) throw new NotFoundException('Product variant not found');

      productIds.add(variant.productId);
      totalItemCount += item.quantity;

      anyRequiresShipping = anyRequiresShipping || Boolean(variant.requiresShipping);

      // subtotal via PriceService
      const resolved = await this.priceService.resolveVariantPrice({
        productVariantId: variant.id,
        productId: variant.productId,
        priceListId: payload.priceListId,
        currencyCode: payload.currencyCode,
        quantity: item.quantity,
      });

      const unitPrice = parseFloat(resolved.unitPrice);
      itemsSubtotal += unitPrice * item.quantity;

      // weight (best effort)
      const weight = Number((variant as any).weight || 0);
      totalWeight += (weight || 0) * item.quantity;
    }

    if (!anyRequiresShipping) return [];

    const currencyCode = payload.currencyCode || 'KES';

    const catalogShipping = await this.catalogShippingContextService.resolveCatalogShippingContext(
      Array.from(productIds),
    );

    const quotes = await this.shippingMatrixService.getQuotes({
      locationId: payload.shippingLocationId,
      subtotal: itemsSubtotal,
      totalWeight,
      itemCount: totalItemCount,
      currencyCode,
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
      method: { id: q.method.id, code: q.method.code, displayName: q.method.displayName },
      rate: { id: q.rate.id, calculationType: q.rate.calculationType, priority: q.rate.priority },
      effectivePriority: q.effectivePriority,
    }));
  }
}
