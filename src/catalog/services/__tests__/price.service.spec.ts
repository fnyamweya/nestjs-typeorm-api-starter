import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { PriceService } from '../price.service';
import { PriceList } from '../../entities/price-list.entity';
import { ProductVariantPrice } from '../../entities/product-variant-price.entity';
import { Currency } from '../../entities/currency.entity';

describe('PriceService', () => {
  let service: PriceService;

  const priceListRepo = {
    findOne: jest.fn(),
    find: jest.fn(),
  };
  const variantPriceRepo = {
    find: jest.fn(),
  };
  const currencyRepo = {
    findOne: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PriceService,
        { provide: getRepositoryToken(PriceList), useValue: priceListRepo },
        { provide: getRepositoryToken(ProductVariantPrice), useValue: variantPriceRepo },
        { provide: getRepositoryToken(Currency), useValue: currencyRepo },
      ],
    }).compile();

    service = module.get<PriceService>(PriceService);
  });

  afterEach(() => jest.resetAllMocks());

  it('resolves price for variant using provided price list', async () => {
    const pl = { id: '1', currencyCode: 'KES', isActive: true } as PriceList;
    priceListRepo.findOne.mockResolvedValue(pl);
    variantPriceRepo.find.mockResolvedValueOnce([
      { unitPrice: '1000.00', compareAtPrice: '1200.00', minQuantity: 1 } as ProductVariantPrice,
    ]);

    const resolved = await service.resolveVariantPrice({ productVariantId: 'pv1', priceListId: '1', quantity: 1 });
    expect(resolved.unitPrice).toBe('1000.00');
    expect(resolved.currencyCode).toBe('KES');
    expect(priceListRepo.findOne).toHaveBeenCalled();
  });

  it('selects price list by currency precedence (meta.priority)', async () => {
    const low = { id: '1', code: 'low', name: 'low', currencyCode: 'KES', isActive: true, metaJson: { priority: 1 }, createdAt: new Date(), updatedAt: new Date() } as PriceList;
    const high = { id: '2', code: 'high', name: 'high', currencyCode: 'KES', isActive: true, metaJson: { priority: 10 }, createdAt: new Date(), updatedAt: new Date() } as PriceList;
    // selectPriceList will call find for currency
    priceListRepo.find.mockResolvedValueOnce([low, high]);
    // variant prices for the higher priority list
    variantPriceRepo.find.mockResolvedValueOnce([
      { unitPrice: '200.00', compareAtPrice: '250.00', minQuantity: 1 } as ProductVariantPrice,
    ]);

    const resolved = await service.resolveVariantPrice({ productVariantId: 'pv1', currencyCode: 'KES', quantity: 1 });
    expect(resolved.unitPrice).toBe('200.00');
    expect(resolved.priceListId).toBe('2');
  });

  it('caches resolved price', async () => {
    const pl = { id: '3', code: 'pl3', name: 'pl3', currencyCode: 'KES', isActive: true, createdAt: new Date(), updatedAt: new Date() } as PriceList;
    priceListRepo.find.mockResolvedValueOnce([pl]);
    variantPriceRepo.find.mockResolvedValueOnce([
      { unitPrice: '100.00', minQuantity: 1 } as ProductVariantPrice,
    ]);

    const r1 = await service.resolveVariantPrice({ productVariantId: 'pv-cache', currencyCode: 'KES', quantity: 1 });
    const r2 = await service.resolveVariantPrice({ productVariantId: 'pv-cache', currencyCode: 'KES', quantity: 1 });

    expect(r1.unitPrice).toBe('100.00');
    expect(r2.unitPrice).toBe('100.00');
    expect(variantPriceRepo.find).toHaveBeenCalledTimes(1);
  });
});
