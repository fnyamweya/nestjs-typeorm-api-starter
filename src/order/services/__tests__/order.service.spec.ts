import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { OrderService } from '../order.service';
import { Order } from '../../entities/order.entity';
import { OrderItem } from '../../entities/order-item.entity';
import { ProductVariant } from '../../../catalog/entities/product-variant.entity';
import { PriceList } from '../../../catalog/entities/price-list.entity';
import { PriceService } from '../../../catalog/services/price.service';

describe('OrderService', () => {
  let service: OrderService;

  const orderRepo = { create: jest.fn(), save: jest.fn() };
  const orderItemRepo = { create: jest.fn(), save: jest.fn() };
  const variantRepo = { findOne: jest.fn() };
  const priceListRepo = { findOne: jest.fn() };
  const priceService = { resolveVariantPrice: jest.fn(), findActivePriceListByCurrency: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        OrderService,
        { provide: getRepositoryToken(Order), useValue: orderRepo },
        { provide: getRepositoryToken(OrderItem), useValue: orderItemRepo },
        { provide: getRepositoryToken(ProductVariant), useValue: variantRepo },
        { provide: getRepositoryToken(PriceList), useValue: priceListRepo },
        { provide: PriceService, useValue: priceService },
      ],
    }).compile();

    service = module.get<OrderService>(OrderService);
  });

  afterEach(() => jest.resetAllMocks());

  it('creates order and items with computed totals', async () => {
    const fakeOrder = { id: '100', orderNumber: 'ORD-1', itemsSubtotal: '0', itemCount: 0 };
    orderRepo.create.mockReturnValue(fakeOrder);
    orderRepo.save.mockResolvedValue({ ...fakeOrder, id: '100' });

    variantRepo.findOne.mockResolvedValue({ id: 'pv1', sku: 'SKU-1', title: 'Variant 1', requiresShipping: true } as ProductVariant);
    priceService.resolveVariantPrice.mockResolvedValue({
      priceListId: '1', currencyCode: 'KES', unitPrice: '100.00', compareAtPrice: '120.00',
    });
    priceService.findActivePriceListByCurrency.mockResolvedValue({ id: '1', currencyCode: 'KES' } as PriceList);

    const payload = {
      customerEmail: 'test@example.com',
      items: [{ productVariantId: 'pv1', quantity: 2 }],
    };

    const result = await service.create(payload as any);
    expect(orderRepo.save).toHaveBeenCalled();
    expect(orderItemRepo.save).toHaveBeenCalled();
    expect(result.grandTotal).toBe('200.0000');
    expect(result.itemCount).toBe(2);
  });
});
