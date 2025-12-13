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
});
