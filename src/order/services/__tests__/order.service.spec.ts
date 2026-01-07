import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { OrderService } from '../order.service';
import { Order } from '../../entities/order.entity';
import { OrderItem } from '../../entities/order-item.entity';
import { ProductSku } from '../../../catalog/entities/product-sku.entity';
import { Product } from '../../../catalog/entities/product.entity';
import { ProductCategory } from '../../../catalog/entities/product-category.entity';
import { Category } from '../../../catalog/entities/category.entity';
import { CategoryClosure } from '../../../catalog/entities/category-closure.entity';
import { PriceList } from '../../../catalog/entities/price-list.entity';
import { PriceService } from '../../../catalog/services/price.service';
import { OrderLevelCharge } from '../../entities/order-level-charge.entity';
import { OrderItemCharge } from '../../entities/order-item-charge.entity';
import { PromotionService } from '../../../promotion/services/promotion.service';
import { TaxService } from '../../services/tax.service';
import { ShippingMatrixService } from '../../../shipping/services/shipping-matrix.service';
import { OrderShippingAddress } from '../../entities/order-shipping-address.entity';
import { User } from '../../../user/entities/user.entity';
import { CatalogShippingContextService } from '../../../shipping/services/catalog-shipping-context.service';
import { Location } from '../../../location/entities/location.entity';
import { CurrencyService } from '../../../currency/currency.service';
import { CustomerShippingAddressService } from '../../../customer-shipping-address/services/customer-shipping-address.service';

describe('OrderService', () => {
  let service: OrderService;

  const orderRepo = { create: jest.fn(), save: jest.fn(), findOne: jest.fn() };
  const orderItemRepo = { create: jest.fn(), save: jest.fn(), find: jest.fn() };
  const skuRepo = { findOne: jest.fn() };
  const productRepo = { find: jest.fn() };
  const productCategoryRepo = { find: jest.fn() };
  const categoryRepo = { find: jest.fn() };
  const categoryClosureRepo = { find: jest.fn() };
  const userRepo = { findOne: jest.fn() };
  const priceListRepo = { findOne: jest.fn() };
  const priceService = {
    resolveSkuPrice: jest.fn(),
    findActivePriceListByCurrency: jest.fn(),
  };
  const orderLevelChargeRepo = { create: jest.fn(), save: jest.fn() };
  const orderItemChargeRepo = { create: jest.fn(), save: jest.fn() };
  const orderShippingAddressRepo = { create: jest.fn(), save: jest.fn() };
  const locationRepo = { findOne: jest.fn() };
  const promotionService = {
    evaluatePromotions: jest.fn(),
    findActivePromotions: jest.fn(),
  };
  const shippingMatrixService = { getQuotes: jest.fn() };
  const taxService = { calculateTax: jest.fn() };
  const catalogShippingContextService = {
    resolveCatalogShippingContext: jest.fn(),
  };
  const currencyService = {
    getDefaultCurrencyCode: jest.fn(),
    assertExists: jest.fn(),
  };
  const customerShippingAddressService = {
    getOptionalForUser: jest.fn(),
    upsertForUser: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        OrderService,
        { provide: getRepositoryToken(Order), useValue: orderRepo },
        { provide: getRepositoryToken(OrderItem), useValue: orderItemRepo },
        {
          provide: getRepositoryToken(OrderItemCharge),
          useValue: orderItemChargeRepo,
        },
        { provide: getRepositoryToken(ProductSku), useValue: skuRepo },
        { provide: getRepositoryToken(Product), useValue: productRepo },
        {
          provide: getRepositoryToken(ProductCategory),
          useValue: productCategoryRepo,
        },
        { provide: getRepositoryToken(Category), useValue: categoryRepo },
        {
          provide: getRepositoryToken(CategoryClosure),
          useValue: categoryClosureRepo,
        },
        { provide: getRepositoryToken(User), useValue: userRepo },
        { provide: getRepositoryToken(PriceList), useValue: priceListRepo },
        {
          provide: getRepositoryToken(OrderLevelCharge),
          useValue: orderLevelChargeRepo,
        },
        {
          provide: getRepositoryToken(OrderShippingAddress),
          useValue: orderShippingAddressRepo,
        },
        { provide: getRepositoryToken(Location), useValue: locationRepo },
        { provide: PriceService, useValue: priceService },
        { provide: PromotionService, useValue: promotionService },
        { provide: ShippingMatrixService, useValue: shippingMatrixService },
        { provide: TaxService, useValue: taxService },
        {
          provide: CatalogShippingContextService,
          useValue: catalogShippingContextService,
        },
        { provide: CurrencyService, useValue: currencyService },
        {
          provide: CustomerShippingAddressService,
          useValue: customerShippingAddressService,
        },
      ],
    }).compile();

    service = module.get<OrderService>(OrderService);
  });

  afterEach(() => jest.resetAllMocks());

  it('creates order and items with computed totals', async () => {
    currencyService.getDefaultCurrencyCode.mockResolvedValue('KES');
    currencyService.assertExists.mockResolvedValue(undefined);

    const fakeOrder: any = {
      id: '100',
      orderNumber: 'ORD-1',
      itemsSubtotal: '0',
      itemCount: 0,
      currencyCode: 'KES',
    };
    orderRepo.create.mockReturnValue(fakeOrder);
    orderRepo.save.mockImplementation(async (o: any) => o);
    orderRepo.findOne.mockResolvedValue(fakeOrder);

    userRepo.findOne.mockResolvedValue({
      id: 'c1',
      email: 'test@example.com',
      firstName: 'Test',
      lastName: 'Customer',
    } as any);

    customerShippingAddressService.getOptionalForUser.mockResolvedValue(null);
    customerShippingAddressService.upsertForUser.mockResolvedValue({
      address: { locationId: 'loc1', countryCode: 'KE', fieldsJson: {} },
    } as any);

    locationRepo.findOne.mockResolvedValue({
      id: 'loc1',
      countryCode: 'KE',
    } as unknown as Location);

    skuRepo.findOne.mockResolvedValue({
      id: 'pv1',
      productId: 'p1',
      sku: 'SKU-1',
      title: 'SKU 1',
      requiresShipping: true,
      attributes: { weight: '1.234' },
    } as unknown as ProductSku);

    priceService.resolveSkuPrice.mockResolvedValue({
      priceListId: '1',
      currencyCode: 'KES',
      unitPrice: '100.00',
      compareAtPrice: '120.00',
    });
    priceService.findActivePriceListByCurrency.mockResolvedValue({
      id: '1',
      currency: 'KES',
    } as unknown as PriceList);
    promotionService.evaluatePromotions.mockResolvedValue({
      applied: [{ code: 'PROMO10', promotionId: 'p1', discount: '20.00' }],
      totalDiscount: '20.00',
    });
    promotionService.findActivePromotions.mockResolvedValue([]);
    shippingMatrixService.getQuotes.mockResolvedValue([
      {
        method: { id: 'm1', displayName: 'Standard', code: 'standard' } as any,
        rate: {
          id: 'r1',
          calculationType: 'flat',
          price: '50.00',
          metaJson: {},
        } as any,
        amount: 50,
      },
    ]);
    taxService.calculateTax.mockResolvedValue({
      amount: 36.8,
      rate: 0.16,
      meta: {},
    });
    catalogShippingContextService.resolveCatalogShippingContext.mockResolvedValue(
      {
        allowedMethodCodes: undefined,
        excludedMethodCodes: undefined,
        ratePriorityBoost: 0,
        productIds: ['p1'],
        categoryIds: [],
        taxonomyIds: [],
      },
    );

    orderShippingAddressRepo.create.mockImplementation((x: any) => x);
    orderShippingAddressRepo.save.mockResolvedValue(undefined);

    orderItemRepo.create.mockImplementation((x: any) => x);
    orderItemRepo.save.mockImplementation(async (x: any) => x);
    orderItemRepo.find.mockResolvedValue([
      {
        id: 'oi1',
        orderId: '100',
        productId: 'p1',
        productSkuId: 'pv1',
        quantity: 2,
        baseSubtotal: '200.0000',
        discountTotal: '0',
        feeTotal: '0',
        taxTotal: '0',
        metaJson: { weight: '1.234' },
      },
    ]);

    orderItemChargeRepo.create.mockImplementation((x: any) => x);
    orderItemChargeRepo.save.mockResolvedValue(undefined);

    productRepo.find.mockResolvedValue([]);
    productCategoryRepo.find.mockResolvedValue([]);
    categoryRepo.find.mockResolvedValue([]);
    categoryClosureRepo.find.mockResolvedValue([]);

    const payload = {
      customerId: 'c1',
      orderItems: [{ productSkuId: 'pv1', quantity: 2 }],
      shippingLocationId: 'loc1',
    };

    const result = await service.create(payload as any);
    expect(orderRepo.save).toHaveBeenCalled();
    expect(orderItemRepo.save).toHaveBeenCalled();

    // ensure SKU weight is persisted to the order item meta so weight-based shipping works
    const createdItem = orderItemRepo.create.mock.calls[0][0];
    expect(createdItem).toBeDefined();
    expect(createdItem.metaJson).toBeDefined();
    expect(createdItem.metaJson.weight).toBe('1.234');
    // ensure a save was eventually triggered
    expect(orderItemRepo.save).toHaveBeenCalled();

    // order-level charges: shipping, promo discount, item tax, shipping tax
    expect(orderLevelChargeRepo.save).toHaveBeenCalledTimes(4);
    // item-level charges: promo discount + item tax
    expect(orderItemChargeRepo.save).toHaveBeenCalledTimes(2);
    expect(result.grandTotal).toBe('266.8000');
    expect(result.discountTotal).toBe('20.0000');
    expect(result.taxTotal).toBe('28.8000');
    expect(result.shippingTax).toBe('8.0000');
    expect(result.itemCount).toBe(2);
  });
});
