import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { PromotionService } from '../promotion.service';
import { Promotion } from '../../entities/promotion.entity';
import { PromotionCondition } from '../../entities/promotion-condition.entity';
import { PromotionAction } from '../../entities/promotion-action.entity';
import { PromotionRedemption } from '../../entities/promotion-redemption.entity';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import {
  ConditionOperator,
  PromotionActionType,
  PromotionConditionType,
  PromotionStatus,
  StackingPolicy,
} from '../../entities/promotion.enums';
import { CurrencyService } from '../../../currency/currency.service';

describe('PromotionService', () => {
  let service: PromotionService;

  const promotionRepo = {
    createQueryBuilder: jest.fn(),
  };

  const redemptionRepo = {
    count: jest.fn(),
  };

  const conditionRepo = {};
  const actionRepo = {};

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PromotionService,
        { provide: getRepositoryToken(Promotion), useValue: promotionRepo },
        {
          provide: getRepositoryToken(PromotionCondition),
          useValue: conditionRepo,
        },
        { provide: getRepositoryToken(PromotionAction), useValue: actionRepo },
        {
          provide: getRepositoryToken(PromotionRedemption),
          useValue: redemptionRepo,
        },
        {
          provide: CurrencyService,
          useValue: {
            assertExists: jest.fn(),
          },
        },
        {
          provide: AppCacheService,
          useValue: {
            remember: jest.fn((_: string, fn: any) => fn()),
            del: jest.fn(),
            delByPrefix: jest.fn(),
          },
        },
      ],
    }).compile();
    service = module.get(PromotionService);
  });

  afterEach(() => jest.resetAllMocks());

  it('applies percent-off promotion (order scope)', async () => {
    const p = {
      id: 'p1',
      code: 'P10',
      channels: [],
      metadata: {},
      status: PromotionStatus.ACTIVE,
      priority: 100,
      stackingPolicy: StackingPolicy.STACKABLE,
      conditions: [],
      actions: [
        {
          type: PromotionActionType.PERCENT_OFF,
          params: { percent: 10 },
          target: { scope: 'order' },
        },
      ],
      createdAt: new Date(),
      updatedAt: new Date(),
    } as unknown as Promotion;

    redemptionRepo.count.mockResolvedValue(0);
    jest.spyOn(service, 'findActivePromotions').mockResolvedValue([p]);

    const r = await service.evaluatePromotions({
      subtotal: '200',
      currencyCode: 'KES',
      shippingFee: '50.00',
    });
    expect(r.totalDiscount).toBe('20.00');
    expect(r.shippingDiscount).toBe('0.00');
    expect(r.applied[0].code).toBe('P10');
  });

  it('skips fixed-off promotion if currency mismatch', async () => {
    const p = {
      id: 'p2',
      code: 'FIX',
      channels: [],
      metadata: {},
      status: PromotionStatus.ACTIVE,
      priority: 100,
      stackingPolicy: StackingPolicy.STACKABLE,
      conditions: [],
      actions: [
        {
          type: PromotionActionType.FIXED_OFF,
          params: { amount: 50, currency: 'USD' },
          target: { scope: 'order' },
        },
      ],
      createdAt: new Date(),
      updatedAt: new Date(),
    } as unknown as Promotion;

    redemptionRepo.count.mockResolvedValue(0);
    jest.spyOn(service, 'findActivePromotions').mockResolvedValue([p]);

    const r = await service.evaluatePromotions({
      subtotal: '200',
      currencyCode: 'KES',
    });
    expect(r.totalDiscount).toBe('0.00');
    expect(r.applied.length).toBe(0);
  });

  it('respects STACKABLE_SAME_GROUP (only one per group)', async () => {
    const p1 = {
      id: 'p1',
      code: 'A',
      status: PromotionStatus.ACTIVE,
      priority: 200,
      stackingPolicy: StackingPolicy.STACKABLE_SAME_GROUP,
      stackingGroup: 'group-1',
      conditions: [
        {
          type: 'first_order',
          operator: ConditionOperator.EQ,
          params: {},
        },
      ],
      actions: [
        {
          type: PromotionActionType.FIXED_OFF,
          params: { amount: 10 },
          target: { scope: 'order' },
        },
      ],
    } as any as Promotion;

    const p2 = {
      id: 'p2',
      code: 'B',
      status: PromotionStatus.ACTIVE,
      priority: 100,
      stackingPolicy: StackingPolicy.STACKABLE_SAME_GROUP,
      stackingGroup: 'group-1',
      conditions: [
        {
          type: 'first_order',
          operator: ConditionOperator.EQ,
          params: {},
        },
      ],
      actions: [
        {
          type: PromotionActionType.FIXED_OFF,
          params: { amount: 10 },
          target: { scope: 'order' },
        },
      ],
    } as any as Promotion;

    redemptionRepo.count.mockResolvedValue(0);
    jest.spyOn(service, 'findActivePromotions').mockResolvedValue([p1, p2]);

    const r = await service.evaluatePromotions({
      subtotal: '200',
      currencyCode: 'KES',
      isFirstOrder: true,
    });
    expect(r.applied.map((x) => x.code)).toEqual(['A']);
    expect(r.totalDiscount).toBe('10.00');
  });

  it('applies promotion when any item matches product/category/taxonomy targeting', async () => {
    const p = {
      id: 'p3',
      code: 'CATALOG',
      status: PromotionStatus.ACTIVE,
      priority: 100,
      stackingPolicy: StackingPolicy.STACKABLE,
      conditions: [
        {
          type: PromotionConditionType.ITEM_IN_PRODUCT,
          operator: ConditionOperator.IN,
          params: { productIds: ['prod-1'] },
        },
        {
          type: PromotionConditionType.ITEM_IN_CATEGORY,
          operator: ConditionOperator.IN,
          params: { categoryIds: ['cat-1'] },
        },
        {
          type: PromotionConditionType.ITEM_IN_TAXONOMY,
          operator: ConditionOperator.IN,
          params: { taxonomyIds: ['tax-1'] },
        },
      ],
      actions: [
        {
          type: PromotionActionType.FIXED_OFF,
          params: { amount: 10 },
          target: { scope: 'order' },
        },
      ],
    } as any as Promotion;

    redemptionRepo.count.mockResolvedValue(0);
    jest.spyOn(service, 'findActivePromotions').mockResolvedValue([p]);

    const r = await service.evaluatePromotions({
      subtotal: '200',
      currencyCode: 'KES',
      items: [
        {
          productId: 'prod-1',
          categoryIds: ['cat-1'],
          taxonomyIds: ['tax-1'],
          quantity: 1,
        },
      ],
    });

    expect(r.applied.map((x) => x.code)).toEqual(['CATALOG']);
    expect(r.totalDiscount).toBe('10.00');
  });

  it('does not apply item-targeted promotion when items are missing', async () => {
    const p = {
      id: 'p4',
      code: 'NEEDS_ITEMS',
      status: PromotionStatus.ACTIVE,
      priority: 100,
      stackingPolicy: StackingPolicy.STACKABLE,
      conditions: [
        {
          type: PromotionConditionType.ITEM_IN_CATEGORY,
          operator: ConditionOperator.IN,
          params: { categoryIds: ['cat-1'] },
        },
      ],
      actions: [
        {
          type: PromotionActionType.FIXED_OFF,
          params: { amount: 10 },
          target: { scope: 'order' },
        },
      ],
    } as any as Promotion;

    redemptionRepo.count.mockResolvedValue(0);
    jest.spyOn(service, 'findActivePromotions').mockResolvedValue([p]);

    const r = await service.evaluatePromotions({
      subtotal: '200',
      currencyCode: 'KES',
    });
    expect(r.applied.length).toBe(0);
    expect(r.totalDiscount).toBe('0.00');
  });

  it('lists public promotions (marketing-safe fields only)', async () => {
    const now = new Date('2026-01-02T12:00:00.000Z');

    const getMany = jest.fn().mockResolvedValue([
      {
        id: 'p-public',
        code: 'WELCOME10',
        name: 'Welcome',
        description: '10% off',
        validFrom: new Date('2026-01-01T00:00:00.000Z'),
        validTo: new Date('2026-12-31T23:59:59.999Z'),
      },
    ]);

    const qb: any = {
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      orderBy: jest.fn().mockReturnThis(),
      addOrderBy: jest.fn().mockReturnThis(),
      getMany,
    };

    // Ensure cache doesn't swallow the call
    const cache = (service as any).cache as AppCacheService;
    (cache.remember as jest.Mock).mockImplementation((_: string, fn: any) =>
      fn(),
    );

    promotionRepo.createQueryBuilder.mockReturnValue(qb);

    const rows = await service.listPublicPromotions({ channel: 'web', now });
    expect(rows).toEqual([
      {
        id: 'p-public',
        code: 'WELCOME10',
        name: 'Welcome',
        description: '10% off',
        validFrom: '2026-01-01T00:00:00.000Z',
        validTo: '2026-12-31T23:59:59.999Z',
      },
    ]);

    // Ensure query builder was used and that channel filter was attempted
    expect(promotionRepo.createQueryBuilder).toHaveBeenCalled();
    expect(qb.andWhere).toHaveBeenCalled();
  });
});
