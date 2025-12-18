import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { ShippingZone } from '../entities/shipping-zone.entity';
import { ShippingZoneLocation } from '../entities/shipping-zone-location.entity';
import { ShippingMethod } from '../entities/shipping-method.entity';
import { ShippingRate } from '../entities/shipping-rate.entity';
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
   * Returns candidate shipping quotes sorted by priority/price.
   * This is intentionally simple and pluggable; supports many rules via ShippingRate.
   */
  async getQuotes(ctx: ShippingContext) {
    // 1. find matching zones by country/region/postal. Keep it simple: country match first.
    const locations = await this.locationRepo.find({ where: { countryCode: ctx.countryCode } });
    const zoneIds = locations.map((l) => l.zoneId);

    if (zoneIds.length === 0) {
      // fallback: global zone (code: 'global')
      const globalZone = await this.zoneRepo.findOne({ where: { code: 'global' } });
      if (!globalZone) return [];
      zoneIds.push(globalZone.id);
    }

    const methods = await this.methodRepo.find({ where: { zoneId: In(zoneIds), isActive: true } });

    const candidates: Array<{ method: ShippingMethod; rate: ShippingRate; amount: number }> = [];

    for (const m of methods) {
      const rates = await this.rateRepo.find({ where: { methodId: m.id }, order: { priority: 'DESC' } });
      for (const r of rates) {
        // check min/max against ctx
        const minWeight = r.minWeight ? parseFloat(r.minWeight) : undefined;
        const maxWeight = r.maxWeight ? parseFloat(r.maxWeight) : undefined;
        const minSubtotal = r.minSubtotal ? parseFloat(r.minSubtotal) : undefined;
        const maxSubtotal = r.maxSubtotal ? parseFloat(r.maxSubtotal) : undefined;

        if (minWeight !== undefined && (ctx.totalWeight ?? 0) < minWeight) continue;
        if (maxWeight !== undefined && (ctx.totalWeight ?? 0) > maxWeight) continue;
        if (minSubtotal !== undefined && ctx.subtotal < minSubtotal) continue;
        if (maxSubtotal !== undefined && ctx.subtotal > maxSubtotal) continue;

        // compute amount depending on calculation type
        let amount = parseFloat(r.price || '0');

        if (r.calculationType === 'per_weight' && ctx.totalWeight !== undefined) {
          const ppu = r.pricePerUnit ? parseFloat(r.pricePerUnit) : 0;
          amount = ppu * (ctx.totalWeight || 0);
        }

        if (r.calculationType === 'per_item' && ctx.itemCount !== undefined) {
          const ppu = r.pricePerUnit ? parseFloat(r.pricePerUnit) : 0;
          amount = ppu * (ctx.itemCount || 0);
        }

        if (r.calculationType === 'table_rate') {
          // metaJson expected to have tiers: [{ upto?: number, price: string }], measure: 'subtotal' | 'weight'
          const meta = r.metaJson as any;
          const tiers = Array.isArray(meta?.tiers) ? meta.tiers : undefined;
          const measure = meta?.measure || 'subtotal';
          if (tiers && tiers.length) {
            let keyVal = measure === 'weight' ? (ctx.totalWeight ?? 0) : ctx.subtotal;
            // find first tier where upto is undefined or keyVal <= upto
            const tier = tiers.find((t: any) => t.upto === undefined || keyVal <= Number(t.upto));
            if (tier) amount = parseFloat(tier.price || amount.toString());
          }
        }

        if (r.calculationType === 'formula') {
          const meta = r.metaJson as any;
          const expr = (meta?.formula as string) || r.price;
          try {
            amount = evaluateFormula(expr, {
              subtotal: ctx.subtotal ?? 0,
              totalWeight: ctx.totalWeight ?? 0,
              itemCount: ctx.itemCount ?? 0,
            });
          } catch (err) {
            // invalid formula -> skip this rate
            continue;
          }
        }

        candidates.push({ method: m, rate: r, amount });
      }
    }

    // sort by amount asc then priority desc
    candidates.sort((a, b) => a.amount - b.amount || b.rate.priority - a.rate.priority);

    return candidates.map((c) => ({ method: c.method, rate: c.rate, amount: c.amount }));
  }
}
