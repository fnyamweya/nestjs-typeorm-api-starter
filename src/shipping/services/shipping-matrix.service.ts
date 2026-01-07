import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { ShippingMethod } from '../entities/shipping-method.entity';
import { ShippingRate } from '../entities/shipping-rate.entity';
import { ShippingZoneLocation } from '../entities/shipping-zone-location.entity';
import { ShippingZone } from '../entities/shipping-zone.entity';
import { ShippingZoneMethod } from '../entities/shipping-zone-method.entity';
import { evaluateFormula } from '../utils/formula-evaluator';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import {
  cacheKeyFromParts,
  cacheKeyHash,
} from 'src/common/cache/cache-key.util';
import { Channel } from 'src/channels/entities/channel.entity';

interface ShippingContext {
  locationId?: string;
  subtotal: number;
  totalWeight?: number;
  itemCount?: number;
  currencyCode?: string;
  channelCode?: string;

  // Optional catalog-derived constraints
  allowedMethodCodes?: string[];
  excludedMethodCodes?: string[];
  ratePriorityBoost?: number;

  // Optional: enable rate targeting via rate.metaJson.{productIds,categoryIds,taxonomyIds}
  productIds?: string[];
  categoryIds?: string[];
  taxonomyIds?: string[];
}

@Injectable()
export class ShippingMatrixService {
  constructor(
    @InjectRepository(ShippingZone)
    private readonly zoneRepo: Repository<ShippingZone>,
    @InjectRepository(ShippingZoneLocation)
    private readonly locationRepo: Repository<ShippingZoneLocation>,
    @InjectRepository(ShippingMethod)
    private readonly methodRepo: Repository<ShippingMethod>,
    @InjectRepository(ShippingZoneMethod)
    private readonly zoneMethodRepo: Repository<ShippingZoneMethod>,
    @InjectRepository(ShippingRate)
    private readonly rateRepo: Repository<ShippingRate>,
    @InjectRepository(Channel)
    private readonly channelRepo: Repository<Channel>,
    private readonly cache: AppCacheService,
  ) {}

  /**
   * Returns candidate shipping quotes sorted by price then rate priority.
   */
  async getQuotes(ctx: ShippingContext) {
    const normalized = {
      locationId: ctx.locationId,
      subtotal: ctx.subtotal,
      totalWeight: ctx.totalWeight,
      itemCount: ctx.itemCount,
      currencyCode: ctx.currencyCode ? String(ctx.currencyCode).toUpperCase() : undefined,
      channelCode: ctx.channelCode ? String(ctx.channelCode).trim() : undefined,
      allowedMethodCodes: (ctx.allowedMethodCodes ?? [])
        .slice()
        .map(String)
        .sort(),
      excludedMethodCodes: (ctx.excludedMethodCodes ?? [])
        .slice()
        .map(String)
        .sort(),
      ratePriorityBoost: ctx.ratePriorityBoost,
      productIds: (ctx.productIds ?? []).slice().map(String).sort(),
      categoryIds: (ctx.categoryIds ?? []).slice().map(String).sort(),
      taxonomyIds: (ctx.taxonomyIds ?? []).slice().map(String).sort(),
    };

    const rawKey = cacheKeyFromParts(
      'shipping',
      'matrix',
      'quotes',
      normalized,
    );
    const key = `shipping:matrix:quotes:${cacheKeyHash(rawKey)}`;

    return this.cache.remember(
      key,
      () => this.computeQuotes({ ...ctx, ...normalized }),
      { ttlSeconds: 60 },
    );
  }

  private async computeQuotes(ctx: ShippingContext) {
        const ctxCurrency = ctx.currencyCode
          ? String(ctx.currencyCode).toUpperCase()
          : undefined;

        const channelCode = ctx.channelCode ? String(ctx.channelCode).trim() : undefined;
        const channelId = channelCode
          ? (
              await this.channelRepo
                .findOne({ where: { code: channelCode }, select: { id: true } as any })
                .catch(() => null)
            )?.id
          : undefined;

    // 1) Find matching zones (locationId-only)
    const zoneIds = await this.resolveZoneIdsByLocation(ctx.locationId);
    if (zoneIds.length === 0) return [];

    // 2) Find active methods attached to those zones
    const zoneMethods = await this.zoneMethodRepo.find({
      where: { zoneId: In(zoneIds), isActive: true },
      relations: ['method'] as any,
    });

    let methods = zoneMethods
      .map((zm) => zm.method)
      .filter((m): m is ShippingMethod => Boolean(m && m.isActive));

    if (ctx.allowedMethodCodes?.length) {
      const allowed = new Set(ctx.allowedMethodCodes);
      methods = methods.filter((m) => allowed.has(m.code));
    }

    if (ctx.excludedMethodCodes?.length) {
      const excluded = new Set(ctx.excludedMethodCodes);
      methods = methods.filter((m) => !excluded.has(m.code));
    }

    const priorityBoost = ctx.ratePriorityBoost ?? 0;
    const productIds = new Set(ctx.productIds ?? []);
    const categoryIds = new Set(ctx.categoryIds ?? []);
    const taxonomyIds = new Set(ctx.taxonomyIds ?? []);
    const candidates: Array<{
      method: ShippingMethod;
      rate: ShippingRate;
      amount: number;
      effectivePriority: number;
    }> = [];

    for (const method of methods) {
      const rates = await this.rateRepo.find({
        where: { methodId: method.id },
        order: { priority: 'DESC' },
        relations: ['channels'] as any,
      });

      for (const rate of rates) {
        // Currency targeting: if the rate is currency-scoped, require a match.
        if (rate.currencyCode && ctxCurrency && rate.currencyCode !== ctxCurrency) {
          continue;
        }
        if (rate.currencyCode && !ctxCurrency) {
          // If caller didn't specify a currency, skip currency-scoped rates.
          continue;
        }

        // Channel targeting: if the rate is channel-scoped, require a match.
        if (rate.channels && rate.channels.length > 0) {
          if (!channelId) continue;
          const ok = rate.channels.some((c) => c.id === channelId);
          if (!ok) continue;
        }

        const meta: any = rate.metaJson || {};

        // Rate targeting (optional): if the rate declares targets, it must match the order context.
        const targetProductIds: string[] | undefined = Array.isArray(
          meta.productIds,
        )
          ? meta.productIds
          : undefined;
        const targetCategoryIds: string[] | undefined = Array.isArray(
          meta.categoryIds,
        )
          ? meta.categoryIds
          : undefined;
        const targetTaxonomyIds: string[] | undefined = Array.isArray(
          meta.taxonomyIds,
        )
          ? meta.taxonomyIds
          : undefined;

        const hasTargets =
          (targetProductIds && targetProductIds.length > 0) ||
          (targetCategoryIds && targetCategoryIds.length > 0) ||
          (targetTaxonomyIds && targetTaxonomyIds.length > 0);

        let targetBonus = 0;
        if (hasTargets) {
          const productMatch =
            targetProductIds?.some((id) => productIds.has(String(id))) ?? false;
          const categoryMatch =
            targetCategoryIds?.some((id) => categoryIds.has(String(id))) ??
            false;
          const taxonomyMatch =
            targetTaxonomyIds?.some((id) => taxonomyIds.has(String(id))) ??
            false;

          if (!productMatch && !categoryMatch && !taxonomyMatch) {
            continue;
          }

          // More specific matches should outrank less specific matches.
          if (productMatch) targetBonus = 300;
          else if (categoryMatch) targetBonus = 200;
          else if (taxonomyMatch) targetBonus = 100;
        }

        const minWeight = rate.minWeight
          ? parseFloat(rate.minWeight)
          : undefined;
        const maxWeight = rate.maxWeight
          ? parseFloat(rate.maxWeight)
          : undefined;
        const minSubtotal = rate.minSubtotal
          ? parseFloat(rate.minSubtotal)
          : undefined;
        const maxSubtotal = rate.maxSubtotal
          ? parseFloat(rate.maxSubtotal)
          : undefined;

        if (minWeight !== undefined && (ctx.totalWeight ?? 0) < minWeight)
          continue;
        if (maxWeight !== undefined && (ctx.totalWeight ?? 0) > maxWeight)
          continue;
        if (minSubtotal !== undefined && ctx.subtotal < minSubtotal) continue;
        if (maxSubtotal !== undefined && ctx.subtotal > maxSubtotal) continue;

        let amount = 0;

        if (rate.calculationType === 'flat') {
          amount = parseFloat(rate.price || '0');
        }

        if (rate.calculationType === 'per_weight') {
          if (ctx.totalWeight === undefined) continue;
          const ppu = rate.pricePerUnit ? parseFloat(rate.pricePerUnit) : 0;
          amount = ppu * ctx.totalWeight;
        }

        if (rate.calculationType === 'per_item') {
          if (ctx.itemCount === undefined) continue;
          const ppu = rate.pricePerUnit ? parseFloat(rate.pricePerUnit) : 0;
          amount = ppu * ctx.itemCount;
        }

        if (rate.calculationType === 'table_rate') {
          const measure = meta.measure || 'subtotal';
          const tiers: any[] = meta.tiers || [];

          const v =
            measure === 'subtotal' ? ctx.subtotal : (ctx.totalWeight ?? 0);
          let matched = tiers.find((t: any) => Number(t.upto) >= Number(v));
          if (!matched && tiers.length > 0) matched = tiers[tiers.length - 1];
          amount = matched ? parseFloat(matched.price) : 0;
        }

        if (rate.calculationType === 'formula') {
          try {
            const expr = String(meta?.formula ?? rate.price ?? '');
            amount = evaluateFormula(expr, {
              subtotal: ctx.subtotal ?? 0,
              totalWeight: ctx.totalWeight ?? 0,
              itemCount: ctx.itemCount ?? 0,
            });
          } catch {
            continue;
          }
        }

        candidates.push({
          method,
          rate,
          amount,
          effectivePriority: (rate.priority ?? 0) + priorityBoost + targetBonus,
        });
      }
    }

    // Priority-first: choose the highest priority candidate; tie-break by lowest amount.
    candidates.sort(
      (a, b) =>
        b.effectivePriority - a.effectivePriority || a.amount - b.amount,
    );

    return candidates;
  }

  private async resolveZoneIdsByLocation(
    locationId?: string,
  ): Promise<string[]> {
    if (!locationId) {
      const globalZone = await this.zoneRepo.findOne({
        where: { code: 'global' },
      });
      return globalZone ? [globalZone.id] : [];
    }

    // Compute ancestors (including self) with depth, smallest depth = most specific.
    // Note: TypeORM's closure-table tree does not always include a `depth` column.
    // We derive it via recursion over `location.parent_id`.
    const rows: Array<{ id_ancestor: string; depth: number }> =
      await this.locationRepo.query(
        `
        WITH RECURSIVE ancestors AS (
          SELECT id AS id_ancestor, parent_id, 0::int AS depth
          FROM "location"
          WHERE id = $1
          UNION ALL
          SELECT l.id AS id_ancestor, l.parent_id, (a.depth + 1)::int AS depth
          FROM "location" l
          INNER JOIN ancestors a ON a.parent_id = l.id
          WHERE a.parent_id IS NOT NULL AND a.depth < 50
        )
        SELECT id_ancestor, depth FROM ancestors ORDER BY depth ASC;
        `,
        [locationId],
      );

    const ancestorDepth = new Map<string, number>();
    for (const r of rows) ancestorDepth.set(r.id_ancestor, Number(r.depth));

    // If the location doesn't exist (or recursion returned nothing), fall back to itself.
    if (!ancestorDepth.size) ancestorDepth.set(locationId, 0);

    const ancestorIds = Array.from(ancestorDepth.keys());
    const matches = await this.locationRepo.find({
      where: { locationId: In(ancestorIds) },
    });

    if (!matches.length) {
      const globalZone = await this.zoneRepo.findOne({
        where: { code: 'global' },
      });
      return globalZone ? [globalZone.id] : [];
    }

    // Choose zones attached to the most specific matching location(s).
    let bestDepth = Number.POSITIVE_INFINITY;
    const zoneDepth = new Map<string, number>();

    for (const m of matches) {
      const d = ancestorDepth.get(m.locationId as string);
      if (d === undefined) continue;
      const prev = zoneDepth.get(m.zoneId);
      if (prev === undefined || d < prev) zoneDepth.set(m.zoneId, d);
      if (d < bestDepth) bestDepth = d;
    }

    const zoneIds = Array.from(zoneDepth.entries())
      .filter(([, d]) => d === bestDepth)
      .map(([zoneId]) => zoneId);

    return zoneIds;
  }
}
