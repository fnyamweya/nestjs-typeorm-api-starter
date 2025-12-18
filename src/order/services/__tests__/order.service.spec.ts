import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { OrderService } from '../order.service';
import { Order } from '../../entities/order.entity';
import { OrderItem } from '../../entities/order-item.entity';
import { ProductVariant } from '../../../catalog/entities/product-variant.entity';
import { PriceList } from '../../../catalog/entities/price-list.entity';
import { PriceService } from '../../../catalog/services/price.service';
import { OrderLevelCharge } from '../../entities/order-level-charge.entity';
import { PromotionService } from '../../../promotion/services/promotion.service';
import { TaxService } from '../../services/tax.service';
import { ShippingMatrixService } from '../../../shipping/services/shipping-matrix.service';

describe('OrderService', () => {
  let service: OrderService;

  const orderRepo = { create: jest.fn(), save: jest.fn() };
  const orderItemRepo = { create: jest.fn(), save: jest.fn() };
  const variantRepo = { findOne: jest.fn() };
  const priceListRepo = { findOne: jest.fn() };
  const priceService = { resolveVariantPrice: jest.fn(), findActivePriceListByCurrency: jest.fn() };
  const orderLevelChargeRepo = { create: jest.fn(), save: jest.fn() };
  const promotionService = { evaluatePromotions: jest.fn(), findActivePromotions: jest.fn() };
  const shippingMatrixService = { getQuotes: jest.fn() };
  const taxService = { calculateTax: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        OrderService,
        { provide: getRepositoryToken(Order), useValue: orderRepo },
        { provide: getRepositoryToken(OrderItem), useValue: orderItemRepo },
        { provide: getRepositoryToken(ProductVariant), useValue: variantRepo },
        { provide: getRepositoryToken(PriceList), useValue: priceListRepo },
        { provide: getRepositoryToken(OrderLevelCharge), useValue: orderLevelChargeRepo },
        { provide: PriceService, useValue: priceService },
        { provide: PromotionService, useValue: promotionService },
        { provide: ShippingMatrixService, useValue: shippingMatrixService },
        { provide: TaxService, useValue: taxService },
      ],
    }).compile();

    service = module.get<OrderService>(OrderService);
  });

  afterEach(() => jest.resetAllMocks());

  it('creates order and items with computed totals', async () => {
    const fakeOrder = { id: '100', orderNumber: 'ORD-1', itemsSubtotal: '0', itemCount: 0 };
    orderRepo.create.mockReturnValue(fakeOrder);
    orderRepo.save.mockResolvedValue({ ...fakeOrder, id: '100' });

    variantRepo.findOne.mockResolvedValue({ id: 'pv1', sku: 'SKU-1', title: 'Variant 1', requiresShipping: true, weight: '1.234' } as ProductVariant);
    priceService.resolveVariantPrice.mockResolvedValue({
      priceListId: '1', currencyCode: 'KES', unitPrice: '100.00', compareAtPrice: '120.00',
    });
    priceService.findActivePriceListByCurrency.mockResolvedValue({ id: '1', currencyCode: 'KES' } as PriceList);
    promotionService.evaluatePromotions.mockResolvedValue({
      applied: [{ code: 'PROMO10', promotionId: 'p1', discount: '20.00' }],
      totalDiscount: '20.00',
    });
    promotionService.findActivePromotions.mockResolvedValue([]);
    shippingMatrixService.getQuotes.mockResolvedValue([{ method: { id: 'm1', displayName: 'Standard' , code: 'standard' } as any, rate: { id: 'r1', calculationType: 'flat', price: '50.00', metaJson: {} } as any, amount: 50 }]);
    taxService.calculateTax.mockResolvedValue({ amount: 36.8, rate: 0.16, meta: {} });

    const payload = {
      customerEmail: 'test@example.com',
      items: [{ productVariantId: 'pv1', quantity: 2 }],
    };

    const result = await service.create(payload as any);
    expect(orderRepo.save).toHaveBeenCalled();
    expect(orderItemRepo.save).toHaveBeenCalled();

    // ensure variant weight is persisted to the order item meta so weight-based shipping works
    const createdItem = orderItemRepo.create.mock.calls[0][0];
    expect(createdItem).toBeDefined();
    expect(createdItem.metaJson).toBeDefined();
    expect(createdItem.metaJson.weight).toBe('1.234');
    // ensure a save was eventually triggered
    expect(orderItemRepo.save).toHaveBeenCalled();

    // discount + shipping + tax charges
    expect(orderLevelChargeRepo.save).toHaveBeenCalledTimes(3);
    expect(result.grandTotal).toBe('266.8000');
    expect(result.discountTotal).toBe('20.00');
    expect(result.taxTotal).toBe('36.8000');
    expect(result.itemCount).toBe(2);
  });
});
