import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { PriceService } from '../price.service';
import { PriceList } from '../../entities/price-list.entity';
import { ProductPrice } from '../../entities/product-price.entity';
import { AppCacheService } from 'src/common/cache/app-cache.service';

describe('PriceService', () => {
  let service: PriceService;

  const priceListRepo = {
    findOne: jest.fn(),
    find: jest.fn(),
  };
  const productPriceRepo = {
    find: jest.fn(),
  };
  const cache = {
    remember: jest.fn(),
  };
  let cacheStore: Map<string, unknown>;

  beforeEach(async () => {
    cacheStore = new Map<string, unknown>();
    cache.remember.mockImplementation(
      async (key: string, factory: () => Promise<unknown>, _options?: { ttlSeconds: number }) => {
        if (cacheStore.has(key)) return cacheStore.get(key);
        const value = await factory();
        cacheStore.set(key, value);
        return value;
      },
    );

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PriceService,
        { provide: getRepositoryToken(PriceList), useValue: priceListRepo },
        { provide: getRepositoryToken(ProductPrice), useValue: productPriceRepo },
        { provide: AppCacheService, useValue: cache },
      ],
    }).compile();

    service = module.get<PriceService>(PriceService);
  });

  afterEach(() => {
    jest.resetAllMocks();
    cacheStore.clear();
  });

  it('resolves price for variant using provided price list', async () => {
    const pl = { id: '1', currencyCode: 'KES', isActive: true } as PriceList;
    priceListRepo.findOne.mockResolvedValue(pl);
    productPriceRepo.find.mockResolvedValueOnce([
      { id: 'p1', unitPrice: '1000.00', compareAtPrice: '1200.00', minQuantity: 1 } as ProductPrice,
    ]);

    const resolved = await service.resolveVariantPrice({ productVariantId: 'pv1', priceListId: '1', quantity: 1 });
    expect(resolved.unitPrice).toBe('1000.00');
    expect(resolved.currencyCode).toBe('KES');
    expect(priceListRepo.findOne).toHaveBeenCalled();
  });

  it('selects price list by currency precedence (meta.priority)', async () => {
    const low = { id: '1', code: 'low', name: 'low', currencyCode: 'KES', isActive: true, metaJson: { priority: 1 }, createdAt: new Date(), updatedAt: new Date() } as PriceList;
    const high = { id: '2', code: 'high', name: 'high', currencyCode: 'KES', isActive: true, metaJson: { priority: 10 }, createdAt: new Date(), updatedAt: new Date() } as PriceList;
    priceListRepo.find.mockResolvedValueOnce([low, high]);
    productPriceRepo.find.mockResolvedValueOnce([
      { id: 'p2', unitPrice: '200.00', compareAtPrice: '250.00', minQuantity: 1 } as ProductPrice,
    ]);

    const resolved = await service.resolveVariantPrice({ productVariantId: 'pv1', currencyCode: 'KES', quantity: 1 });
    expect(resolved.unitPrice).toBe('200.00');
    expect(resolved.priceListId).toBe('2');
  });

  it('caches resolved price', async () => {
    const pl = { id: '3', code: 'pl3', name: 'pl3', currencyCode: 'KES', isActive: true, createdAt: new Date(), updatedAt: new Date() } as PriceList;
    priceListRepo.find.mockResolvedValueOnce([pl]);
    productPriceRepo.find.mockResolvedValueOnce([
      { id: 'p3', unitPrice: '100.00', minQuantity: 1 } as unknown as ProductPrice,
    ]);

    const r1 = await service.resolveVariantPrice({ productVariantId: 'pv-cache', currencyCode: 'KES', quantity: 1 });
    const r2 = await service.resolveVariantPrice({ productVariantId: 'pv-cache', currencyCode: 'KES', quantity: 1 });

    expect(r1.unitPrice).toBe('100.00');
    expect(r2.unitPrice).toBe('100.00');
    expect(productPriceRepo.find).toHaveBeenCalledTimes(1);
  });

  it('prefers context-matched prices over generic ones', async () => {
    const pl = { id: 'ctx', currencyCode: 'KES', isActive: true } as PriceList;
    priceListRepo.findOne.mockResolvedValue(pl);
    productPriceRepo.find.mockResolvedValueOnce([
      {
        id: 'p4',
        unitPrice: '90.00',
        minQuantity: 1,
        metaJson: { conditions: { customerGroupIds: ['vip'] } },
      } as unknown as ProductPrice,
      { id: 'p5', unitPrice: '100.00', minQuantity: 1, metaJson: {} } as unknown as ProductPrice,
    ]);

    const resolved = await service.resolveVariantPrice({
      productVariantId: 'pv1',
      priceListId: 'ctx',
      quantity: 1,
      context: { customerGroupId: 'vip' },
    });

    expect(resolved.unitPrice).toBe('90.00');
  });
});
