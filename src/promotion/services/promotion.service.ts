import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Promotion } from '../entities/promotion.entity';
import {
  ConditionOperator,
  PromotionActionType,
  PromotionConditionType,
  PromotionStatus,
  StackingPolicy,
} from '../entities/promotion.enums';
import { PromotionRedemption } from '../entities/promotion-redemption.entity';
import { PromotionCondition } from '../entities/promotion-condition.entity';
import { PromotionAction } from '../entities/promotion-action.entity';
import { CreatePromotionDto } from '../dto/create-promotion.dto';
import { UpdatePromotionDto } from '../dto/update-promotion.dto';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import {
  cacheKeyFromParts,
  cacheKeyHash,
} from 'src/common/cache/cache-key.util';
import { CurrencyService } from 'src/currency/currency.service';

export interface AppliedPromotion {
  code: string;
  promotionId: string;
  discount: string; // order-level discount
  shippingDiscount?: string;
}

export type PublicPromotion = {
  id: string;
  code: string;
  name?: string;
  description?: string;
  validFrom?: string;
  validTo?: string;
};

export type PromotionLineItemContext = {
  productId?: string;
  productSkuId?: string;
  quantity?: number;
  categoryIds?: string[];
  taxonomyIds?: string[];
  tags?: string[];
};

export type PromotionEvaluationContext = {
  subtotal: string;
  currencyCode: string;
  shippingFee?: string;
  customerId?: string;
  channel?: string;
  isFirstOrder?: boolean;
  items?: PromotionLineItemContext[];
};

type ConditionEvaluator = (
  ctx: PromotionEvaluationContext,
  operator: ConditionOperator,
  params: Record<string, unknown>,
) => boolean;
type ActionApplier = (
  ctx: PromotionEvaluationContext,
  params: Record<string, unknown>,
  target: Record<string, unknown>,
) => { orderDiscount: number; shippingDiscount: number };

@Injectable()
export class PromotionService {
  constructor(
    @InjectRepository(Promotion)
    private readonly promotionRepo: Repository<Promotion>,
    @InjectRepository(PromotionCondition)
    private readonly conditionRepo: Repository<PromotionCondition>,
    @InjectRepository(PromotionAction)
    private readonly actionRepo: Repository<PromotionAction>,
    @InjectRepository(PromotionRedemption)
    private readonly redemptionRepo: Repository<PromotionRedemption>,
    private readonly cache: AppCacheService,
    private readonly currencyService: CurrencyService,
  ) {}

  private async normalizeAndValidateEmbeddedCurrency(
    params: Record<string, unknown> | undefined,
  ): Promise<Record<string, unknown>> {
    const p = params ?? {};
    const raw = (p as any).currency;
    if (typeof raw === 'undefined' || raw === null || raw === '') return p;

    const currency = await this.currencyService.assertExists(raw);
    return { ...p, currency };
  }

  async listPromotions(): Promise<Promotion[]> {
    return this.cache.remember(
      'promotions:list',
      () =>
        this.promotionRepo.find({
          relations: ['conditions', 'actions'],
          order: { createdAt: 'DESC' as any },
        }),
      { ttlSeconds: 60 },
    );
  }

  async listPublicPromotions(opts?: {
    channel?: string;
    now?: Date;
  }): Promise<PublicPromotion[]> {
    const channel = opts?.channel?.trim() || undefined;
    const key = `promotions:public:${channel ?? 'all'}`;

    return this.cache.remember(
      key,
      async () => {
        const now = opts?.now ?? new Date();

        const qb = this.promotionRepo
          .createQueryBuilder('p')
          .select([
            'p.id',
            'p.code',
            'p.name',
            'p.description',
            'p.validFrom',
            'p.validTo',
          ])
          .where('p.status = :status', { status: PromotionStatus.ACTIVE })
          .andWhere('(p.validFrom IS NULL OR p.validFrom <= :now)', { now })
          .andWhere('(p.validTo IS NULL OR p.validTo >= :now)', { now })
          .orderBy('p.priority', 'ASC')
          .addOrderBy('p.createdAt', 'DESC');

        if (channel) {
          qb.andWhere(
            "(p.channels = '[]'::jsonb OR p.channels @> :channelJson::jsonb)",
            { channelJson: JSON.stringify([channel]) },
          );
        }

        const rows = await qb.getMany();
        return rows.map((p) => ({
          id: p.id,
          code: p.code,
          name: p.name ?? undefined,
          description: p.description ?? undefined,
          validFrom: p.validFrom ? p.validFrom.toISOString() : undefined,
          validTo: p.validTo ? p.validTo.toISOString() : undefined,
        }));
      },
      { ttlSeconds: 60 },
    );
  }

  async getPromotion(id: string): Promise<Promotion> {
    const key = `promotions:byId:${id}`;
    const p = await this.cache.remember(
      key,
      () =>
        this.promotionRepo.findOne({
          where: { id },
          relations: ['conditions', 'actions'],
        }),
      { ttlSeconds: 300 },
    );
    if (!p) throw new NotFoundException('Promotion not found');
    return p;
  }

  async createPromotion(dto: CreatePromotionDto): Promise<Promotion> {
    if (!dto.actions?.length) {
      throw new BadRequestException('At least one action is required');
    }

    const created = await this.promotionRepo.manager.transaction(
      async (manager) => {
        const promoRepo = manager.getRepository(Promotion);
        const actionRepo = manager.getRepository(PromotionAction);
        const conditionRepo = manager.getRepository(PromotionCondition);

        const promotion = promoRepo.create({
          code: dto.code,
          name: dto.name,
          description: dto.description,
          status: dto.status,
          priority: dto.priority,
          stackingPolicy: dto.stackingPolicy,
          stackingGroup: dto.stackingGroup,
          maxRedemptions: dto.maxRedemptions,
          maxRedemptionsPerCustomer: dto.maxRedemptionsPerCustomer,
          validFrom: dto.validFrom ? new Date(dto.validFrom) : undefined,
          validTo: dto.validTo ? new Date(dto.validTo) : undefined,
          channels: dto.channels ?? [],
          metadata: dto.metadata ?? {},
        });

        promotion.actions = [];
        for (const a of dto.actions) {
          const params = await this.normalizeAndValidateEmbeddedCurrency(
            (a as any).params,
          );
          promotion.actions.push(
            actionRepo.create({
              type: a.type,
              params,
              target: a.target ?? {},
              promotion,
            }),
          );
        }

        promotion.conditions = [];
        for (const c of dto.conditions ?? []) {
          const params = await this.normalizeAndValidateEmbeddedCurrency(
            (c as any).params,
          );
          promotion.conditions.push(
            conditionRepo.create({
              type: c.type,
              operator: c.operator,
              params,
              promotion,
            }),
          );
        }

        const saved = await promoRepo.save(promotion);
        return promoRepo.findOneOrFail({
          where: { id: saved.id },
          relations: ['conditions', 'actions'],
        });
      },
    );

    await this.cache.delByPrefix('promotions:');
    return created;
  }

  async updatePromotion(
    id: string,
    dto: UpdatePromotionDto,
  ): Promise<Promotion> {
    const updated = await this.promotionRepo.manager.transaction(
      async (manager) => {
        const promoRepo = manager.getRepository(Promotion);
        const actionRepo = manager.getRepository(PromotionAction);
        const conditionRepo = manager.getRepository(PromotionCondition);

        const promotion = await promoRepo.findOne({
          where: { id },
          relations: ['conditions', 'actions'],
        });
        if (!promotion) throw new NotFoundException('Promotion not found');

        if (typeof dto.code !== 'undefined') promotion.code = dto.code;
        if (typeof dto.name !== 'undefined') promotion.name = dto.name;
        if (typeof dto.description !== 'undefined')
          promotion.description = dto.description;
        if (typeof dto.status !== 'undefined') promotion.status = dto.status;
        if (typeof dto.priority !== 'undefined')
          promotion.priority = dto.priority;
        if (typeof dto.stackingPolicy !== 'undefined')
          promotion.stackingPolicy = dto.stackingPolicy;
        if (typeof dto.stackingGroup !== 'undefined')
          promotion.stackingGroup = dto.stackingGroup;
        if (typeof dto.maxRedemptions !== 'undefined')
          promotion.maxRedemptions = dto.maxRedemptions;
        if (typeof dto.maxRedemptionsPerCustomer !== 'undefined')
          promotion.maxRedemptionsPerCustomer = dto.maxRedemptionsPerCustomer;
        if (typeof dto.validFrom !== 'undefined')
          promotion.validFrom = dto.validFrom
            ? new Date(dto.validFrom)
            : undefined;
        if (typeof dto.validTo !== 'undefined')
          promotion.validTo = dto.validTo ? new Date(dto.validTo) : undefined;
        if (typeof dto.channels !== 'undefined')
          promotion.channels = dto.channels ?? [];
        if (typeof dto.metadata !== 'undefined')
          promotion.metadata = dto.metadata ?? {};

        // Replace nested relations when provided
        if (typeof dto.conditions !== 'undefined') {
          await conditionRepo.delete({ promotionId: id });
          promotion.conditions = [];
          for (const c of dto.conditions ?? []) {
            const params = await this.normalizeAndValidateEmbeddedCurrency(
              (c as any).params,
            );
            promotion.conditions.push(
              conditionRepo.create({
                type: c.type,
                operator: c.operator,
                params,
                promotion,
              }),
            );
          }
        }

        if (typeof dto.actions !== 'undefined') {
          if (!(dto.actions ?? []).length) {
            throw new BadRequestException('At least one action is required');
          }
          await actionRepo.delete({ promotionId: id });
          promotion.actions = [];
          for (const a of dto.actions ?? []) {
            const params = await this.normalizeAndValidateEmbeddedCurrency(
              (a as any).params,
            );
            promotion.actions.push(
              actionRepo.create({
                type: a.type,
                params,
                target: a.target ?? {},
                promotion,
              }),
            );
          }
        }

        await promoRepo.save(promotion);
        return promoRepo.findOneOrFail({
          where: { id },
          relations: ['conditions', 'actions'],
        });
      },
    );

    await this.cache.delByPrefix('promotions:');
    return updated;
  }

  async deletePromotion(id: string): Promise<{ deleted: boolean }> {
    const res = await this.promotionRepo.delete(id);
    const deleted = (res.affected ?? 0) > 0;
    if (deleted) {
      await this.cache.delByPrefix('promotions:');
    }
    return { deleted };
  }

  private normalizeStringArray(value: unknown): string[] {
    if (!Array.isArray(value)) return [];
    return value
      .map((v) => String(v))
      .map((v) => v.trim())
      .filter(Boolean);
  }

  private extractIds(
    params: Record<string, unknown>,
    keys: string[],
  ): string[] {
    for (const k of keys) {
      const v = (params as any)?.[k];
      if (Array.isArray(v)) {
        const ids = this.normalizeStringArray(v);
        if (ids.length) return ids;
      }
      if (typeof v === 'string' && v.trim()) return [v.trim()];
    }
    return [];
  }

  private unionItemIds(
    ctx: PromotionEvaluationContext,
    kind: 'product' | 'category' | 'taxonomy' | 'tag',
  ): Set<string> {
    const out = new Set<string>();
    const items = ctx.items ?? [];
    for (const it of items) {
      if (!it) continue;
      if (kind === 'product' && it.productId) out.add(String(it.productId));
      if (kind === 'category')
        (it.categoryIds ?? []).forEach((x) => out.add(String(x)));
      if (kind === 'taxonomy')
        (it.taxonomyIds ?? []).forEach((x) => out.add(String(x)));
      if (kind === 'tag') (it.tags ?? []).forEach((x) => out.add(String(x)));
    }
    return out;
  }

  private matchSetByOperator(
    operator: ConditionOperator,
    itemValues: Set<string>,
    expected: string[],
  ): boolean {
    if (!expected.length) return false;
    if (!itemValues.size) return false;

    const hasAny = expected.some((id) => itemValues.has(String(id)));

    switch (operator) {
      case ConditionOperator.EQ:
      case ConditionOperator.IN:
      case ConditionOperator.CONTAINS:
        return hasAny;
      case ConditionOperator.NEQ:
      case ConditionOperator.NOT_IN:
        return !hasAny;
      default:
        return false;
    }
  }

  private readonly conditionEvaluators: Record<
    PromotionConditionType,
    ConditionEvaluator
  > = {
    [PromotionConditionType.CART_TOTAL]: (ctx, operator, params) => {
      const amount = Number((params as any)?.amount ?? 0);
      const currency = (params as any)?.currency as string | undefined;
      if (currency && currency !== ctx.currencyCode) return false;

      const subtotal = Number(ctx.subtotal || '0');
      switch (operator) {
        case ConditionOperator.GT:
          return subtotal > amount;
        case ConditionOperator.GTE:
          return subtotal >= amount;
        case ConditionOperator.LT:
          return subtotal < amount;
        case ConditionOperator.LTE:
          return subtotal <= amount;
        case ConditionOperator.EQ:
          return subtotal === amount;
        case ConditionOperator.NEQ:
          return subtotal !== amount;
        default:
          return false;
      }
    },
    [PromotionConditionType.FIRST_ORDER]: (ctx, operator) => {
      const isFirst = Boolean(ctx.isFirstOrder);
      if (operator === ConditionOperator.EQ) return isFirst;
      if (operator === ConditionOperator.NEQ) return !isFirst;
      return false;
    },
    [PromotionConditionType.HAS_COUPON]: () => true,
    [PromotionConditionType.CUSTOMER_SEGMENT]: () => true,
    [PromotionConditionType.ITEM_IN_PRODUCT]: (ctx, operator, params) => {
      if (!ctx.items?.length) return false;
      const ids = this.extractIds(params, [
        'productIds',
        'productId',
        'ids',
        'id',
      ]);
      const itemValues = this.unionItemIds(ctx, 'product');
      return this.matchSetByOperator(operator, itemValues, ids);
    },
    [PromotionConditionType.ITEM_IN_CATEGORY]: (ctx, operator, params) => {
      if (!ctx.items?.length) return false;
      const ids = this.extractIds(params, [
        'categoryIds',
        'categoryId',
        'ids',
        'id',
      ]);
      const itemValues = this.unionItemIds(ctx, 'category');
      return this.matchSetByOperator(operator, itemValues, ids);
    },
    [PromotionConditionType.ITEM_IN_TAXONOMY]: (ctx, operator, params) => {
      if (!ctx.items?.length) return false;
      const ids = this.extractIds(params, [
        'taxonomyIds',
        'taxonomyId',
        'ids',
        'id',
      ]);
      const itemValues = this.unionItemIds(ctx, 'taxonomy');
      return this.matchSetByOperator(operator, itemValues, ids);
    },
    [PromotionConditionType.ITEM_HAS_TAG]: (ctx, operator, params) => {
      if (!ctx.items?.length) return false;
      const tags = this.extractIds(params, ['tags', 'tag', 'ids', 'id']);
      const itemValues = this.unionItemIds(ctx, 'tag');
      return this.matchSetByOperator(operator, itemValues, tags);
    },
    [PromotionConditionType.PAYMENT_METHOD]: () => true,
  };

  private readonly actionAppliers: Record<PromotionActionType, ActionApplier> =
    {
      [PromotionActionType.PERCENT_OFF]: (ctx, params, target) => {
        const percent = Number((params as any)?.percent ?? 0);
        if (!Number.isFinite(percent) || percent <= 0)
          return { orderDiscount: 0, shippingDiscount: 0 };

        const scope = (target as any)?.scope ?? 'order';
        if (scope === 'shipping') {
          const shippingFee = Number(ctx.shippingFee || '0');
          const discount = (shippingFee * percent) / 100;
          return { orderDiscount: 0, shippingDiscount: Math.max(0, discount) };
        }

        const subtotal = Number(ctx.subtotal || '0');
        const discount = (subtotal * percent) / 100;
        return { orderDiscount: Math.max(0, discount), shippingDiscount: 0 };
      },
      [PromotionActionType.FIXED_OFF]: (ctx, params, target) => {
        const amount = Number((params as any)?.amount ?? 0);
        const currency = (params as any)?.currency as string | undefined;
        if (!Number.isFinite(amount) || amount <= 0)
          return { orderDiscount: 0, shippingDiscount: 0 };
        if (currency && currency !== ctx.currencyCode)
          return { orderDiscount: 0, shippingDiscount: 0 };

        const scope = (target as any)?.scope ?? 'order';
        if (scope === 'shipping') {
          return { orderDiscount: 0, shippingDiscount: amount };
        }

        return { orderDiscount: amount, shippingDiscount: 0 };
      },
      [PromotionActionType.FREE_SHIPPING]: (ctx) => {
        const shippingFee = Number(ctx.shippingFee || '0');
        return { orderDiscount: 0, shippingDiscount: Math.max(0, shippingFee) };
      },
      [PromotionActionType.BOGO]: () => ({
        orderDiscount: 0,
        shippingDiscount: 0,
      }),
      [PromotionActionType.TIERED_DISCOUNT]: () => ({
        orderDiscount: 0,
        shippingDiscount: 0,
      }),
      [PromotionActionType.GIFT_ITEM]: () => ({
        orderDiscount: 0,
        shippingDiscount: 0,
      }),
    };

  async findActivePromotions(currencyCode?: string) {
    const rawKey = cacheKeyFromParts('promotions', 'active', {
      currencyCode: currencyCode ?? null,
    });
    const key = `promotions:active:${cacheKeyHash(rawKey)}`;

    return this.cache.remember(
      key,
      async () => {
        const now = new Date();
        const qb = this.promotionRepo
          .createQueryBuilder('p')
          .leftJoinAndSelect('p.conditions', 'c')
          .leftJoinAndSelect('p.actions', 'a')
          .where('p.status = :status', { status: PromotionStatus.ACTIVE })
          .andWhere('(p.validFrom IS NULL OR p.validFrom <= :now)', { now })
          .andWhere('(p.validTo IS NULL OR p.validTo >= :now)', { now });

        // Currency filtering is optional; we keep it broad by default since percent/free-shipping may be currency-agnostic.
        // If callers want strict filtering they can implement it via conditions/actions params.
        const promos = await qb.getMany();
        if (!currencyCode) return promos;
        return promos;
      },
      { ttlSeconds: 60 },
    );
  }

  /**
   * Evaluate promotions against a simple order context
   * This is intentionally simple: it will apply percentage and fixed discounts
   */
  async evaluatePromotions(orderContext: PromotionEvaluationContext) {
    const subtotal = Number(orderContext.subtotal || '0');
    const shippingFee = Number(orderContext.shippingFee || '0');

    const promos = await this.findActivePromotions(orderContext.currencyCode);
    const sorted = [...promos].sort(
      (a, b) => (b.priority ?? 0) - (a.priority ?? 0),
    );

    const applied: AppliedPromotion[] = [];
    const appliedStackingGroups = new Set<string>();
    let totalDiscount = 0;
    let shippingDiscount = 0;
    let anyExclusiveApplied = false;

    for (const p of sorted) {
      if (anyExclusiveApplied) break;

      // Redemption caps (best-effort; only enforced if relevant context is provided)
      if (p.maxRedemptions) {
        const total = await this.redemptionRepo.count({
          where: { promotionId: p.id },
        });
        if (total >= p.maxRedemptions) continue;
      }
      if (p.maxRedemptionsPerCustomer && orderContext.customerId) {
        const perCustomer = await this.redemptionRepo.count({
          where: { promotionId: p.id, customerId: orderContext.customerId },
        });
        if (perCustomer >= p.maxRedemptionsPerCustomer) continue;
      }

      if (
        p.stackingPolicy === StackingPolicy.STACKABLE_SAME_GROUP &&
        p.stackingGroup
      ) {
        if (appliedStackingGroups.has(p.stackingGroup)) continue;
      }

      const conditions = p.conditions ?? [];
      const allMatch = conditions.every((c) => {
        const evaluator = this.conditionEvaluators[c.type];
        if (!evaluator) return false;
        return evaluator(orderContext, c.operator, (c.params || {}) as any);
      });

      if (!allMatch) continue;

      let promoOrderDiscount = 0;
      let promoShippingDiscount = 0;

      for (const a of p.actions ?? []) {
        const applier = this.actionAppliers[a.type];
        if (!applier) continue;
        const r = applier(
          orderContext,
          (a.params || {}) as any,
          (a.target || {}) as any,
        );
        promoOrderDiscount += r.orderDiscount;
        promoShippingDiscount += r.shippingDiscount;
      }

      // Cap to remaining amounts
      const orderRemaining = Math.max(0, subtotal - totalDiscount);
      const shipRemaining = Math.max(0, shippingFee - shippingDiscount);
      promoOrderDiscount = Math.min(
        Math.max(0, promoOrderDiscount),
        orderRemaining,
      );
      promoShippingDiscount = Math.min(
        Math.max(0, promoShippingDiscount),
        shipRemaining,
      );

      if (promoOrderDiscount <= 0 && promoShippingDiscount <= 0) continue;

      applied.push({
        code: p.code,
        promotionId: p.id,
        discount: promoOrderDiscount.toFixed(2),
        shippingDiscount:
          promoShippingDiscount > 0
            ? promoShippingDiscount.toFixed(2)
            : undefined,
      });
      totalDiscount += promoOrderDiscount;
      shippingDiscount += promoShippingDiscount;

      if (p.stackingPolicy === StackingPolicy.EXCLUSIVE)
        anyExclusiveApplied = true;
      if (
        p.stackingPolicy === StackingPolicy.STACKABLE_SAME_GROUP &&
        p.stackingGroup
      ) {
        appliedStackingGroups.add(p.stackingGroup);
      }
    }

    return {
      applied,
      totalDiscount: totalDiscount.toFixed(2),
      shippingDiscount: shippingDiscount.toFixed(2),
    };
  }
}
