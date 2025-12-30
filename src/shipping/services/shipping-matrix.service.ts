import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { ShippingMethod } from '../entities/shipping-method.entity';
import { ShippingRate } from '../entities/shipping-rate.entity';
import { ShippingZoneLocation } from '../entities/shipping-zone-location.entity';
import { ShippingZone } from '../entities/shipping-zone.entity';
import { evaluateFormula } from '../utils/formula-evaluator';

interface ShippingContext {
  countryCode?: string;
  region?: string;
  postalCode?: string;
  subtotal: number;
  totalWeight?: number;
  itemCount?: number;
  currencyCode?: string;
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
    @InjectRepository(ShippingRate)
    private readonly rateRepo: Repository<ShippingRate>,
  ) {}

  /**
   * Returns candidate shipping quotes sorted by price then rate priority.
   */
  async getQuotes(ctx: ShippingContext) {
    // 1) Find matching zones
    const locations = await this.locationRepo.find({ where: { countryCode: ctx.countryCode } });
    const zoneIds = locations.map((l) => l.zoneId);

    if (zoneIds.length === 0) {
      const globalZone = await this.zoneRepo.findOne({ where: { code: 'global' } });
      if (!globalZone) return [];
      zoneIds.push(globalZone.id);
    }

    // 2) Find active methods in those zones
    const methods = await this.methodRepo.find({ where: { zoneId: In(zoneIds), isActive: true } });

    const candidates: Array<{ method: ShippingMethod; rate: ShippingRate; amount: number }> = [];

    for (const method of methods) {
      const rates = await this.rateRepo.find({ where: { methodId: method.id }, order: { priority: 'DESC' } });

      for (const rate of rates) {
        const minWeight = rate.minWeight ? parseFloat(rate.minWeight) : undefined;
        const maxWeight = rate.maxWeight ? parseFloat(rate.maxWeight) : undefined;
        const minSubtotal = rate.minSubtotal ? parseFloat(rate.minSubtotal) : undefined;
        const maxSubtotal = rate.maxSubtotal ? parseFloat(rate.maxSubtotal) : undefined;

        if (minWeight !== undefined && (ctx.totalWeight ?? 0) < minWeight) continue;
        if (maxWeight !== undefined && (ctx.totalWeight ?? 0) > maxWeight) continue;
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
          const meta: any = rate.metaJson || {};
          const measure = meta.measure || 'subtotal';
          const tiers: any[] = meta.tiers || [];

          const v = measure === 'subtotal' ? ctx.subtotal : (ctx.totalWeight ?? 0);
          let matched = tiers.find((t: any) => Number(t.upto) >= Number(v));
          if (!matched && tiers.length > 0) matched = tiers[tiers.length - 1];
          amount = matched ? parseFloat(matched.price) : 0;
        }

        if (rate.calculationType === 'formula') {
          try {
            const meta = rate.metaJson as any;
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

        candidates.push({ method, rate, amount });
      }
    }

    candidates.sort((a, b) => a.amount - b.amount || b.rate.priority - a.rate.priority);

    return candidates;
  }
}
