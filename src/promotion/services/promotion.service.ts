import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Promotion } from '../entities/promotion.entity';

export interface AppliedPromotion {
  code: string;
  promotionId: string;
  discount: string; // numeric string
}

@Injectable()
export class PromotionService {
  constructor(
    @InjectRepository(Promotion)
    private readonly promotionRepo: Repository<Promotion>,
  ) {}

  async findActivePromotions(currencyCode?: string) {
    const now = new Date();
    const where: any = { isActive: true };
    if (currencyCode) where.currencyCode = currencyCode;
    const promos = await this.promotionRepo.find({ where });
    return promos.filter((p) => {
      if (p.validFrom && p.validFrom > now) return false;
      if (p.validTo && p.validTo < now) return false;
      return true;
    });
  }

  /**
   * Evaluate promotions against a simple order context
   * This is intentionally simple: it will apply percentage and fixed discounts
   */
  async evaluatePromotions(orderContext: { subtotal: string; currencyCode: string }) {
    const subtotal = Number(orderContext.subtotal || '0');
    const promos = await this.findActivePromotions(orderContext.currencyCode);
    const applied: AppliedPromotion[] = [];
    let totalDiscount = 0;

    for (const p of promos) {
      if (p.type === 'percentage') {
        const pct = Number(p.value || '0');
        const disc = (subtotal * pct) / 100;
        const d = Math.min(disc, subtotal - totalDiscount);
        if (d > 0) {
          applied.push({ code: p.code, promotionId: p.id, discount: d.toFixed(2) });
          totalDiscount += d;
        }
      } else if (p.type === 'fixed') {
        const amt = Number(p.value || '0');
        if (p.currencyCode && p.currencyCode !== orderContext.currencyCode) continue;
        const d = Math.min(amt, subtotal - totalDiscount);
        if (d > 0) {
          applied.push({ code: p.code, promotionId: p.id, discount: d.toFixed(2) });
          totalDiscount += d;
        }
      }
      // free_shipping would be handled at order-level when shipping is present
    }

    return { applied, totalDiscount: totalDiscount.toFixed(2) };
  }
}
