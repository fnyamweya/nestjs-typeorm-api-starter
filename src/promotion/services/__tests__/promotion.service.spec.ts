import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { PromotionService } from '../promotion.service';
import { Promotion } from '../../entities/promotion.entity';

describe('PromotionService', () => {
  let service: PromotionService;

  const repo = {
    find: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PromotionService,
        { provide: getRepositoryToken(Promotion), useValue: repo },
      ],
    }).compile();
    service = module.get(PromotionService);
  });

  afterEach(() => jest.resetAllMocks());

  it('applies percentage promotion', async () => {
    const now = new Date();
    const p = { id: '1', code: 'P10', type: 'percentage', value: '10', isActive: true, validFrom: undefined, validTo: undefined } as Promotion;
    repo.find.mockResolvedValueOnce([p]);

    const r = await service.evaluatePromotions({ subtotal: '200', currencyCode: 'KES' });
    expect(r.totalDiscount).toBe('20.00');
    expect(r.applied[0].code).toBe('P10');
  });

  it('skips fixed promotion if currency mismatch', async () => {
    const p = { id: '2', code: 'FIX', type: 'fixed', value: '50', currencyCode: 'USD', isActive: true } as Promotion;
    repo.find.mockResolvedValueOnce([p]);

    const r = await service.evaluatePromotions({ subtotal: '200', currencyCode: 'KES' });
    expect(r.totalDiscount).toBe('0.00');
    expect(r.applied.length).toBe(0);
  });

  it('respects validity window', async () => {
    const future = new Date(Date.now() + 1000 * 60 * 60 * 24);
    const p = { id: '3', code: 'FUT', type: 'fixed', value: '10', currencyCode: 'KES', isActive: true, validFrom: future } as Promotion;
    repo.find.mockResolvedValueOnce([p]);

    const r = await service.evaluatePromotions({ subtotal: '200', currencyCode: 'KES' });
    expect(r.totalDiscount).toBe('0.00');
  });
});
