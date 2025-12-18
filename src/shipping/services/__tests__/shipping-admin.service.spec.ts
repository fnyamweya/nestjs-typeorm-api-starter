import { ShippingAdminService } from '../shipping-admin.service';
import { BadRequestException } from '@nestjs/common';

function mockRepo(overrides: Partial<any> = {}) {
  return {
    create: jest.fn((v: any) => v),
    save: jest.fn((v: any) => Promise.resolve({ ...v, id: 'r1' })),
    update: jest.fn().mockResolvedValue(undefined),
    findOne: jest.fn().mockResolvedValue(undefined),
    find: jest.fn().mockResolvedValue([]),
    delete: jest.fn().mockResolvedValue({ affected: 1 }),
    ...overrides,
  } as any;
}

describe('ShippingAdminService', () => {
  let svc: ShippingAdminService;
  let zoneRepo: any;
  let methodRepo: any;
  let rateRepo: any;

  beforeEach(() => {
    zoneRepo = mockRepo();
    methodRepo = mockRepo();
    rateRepo = mockRepo();

    svc = new ShippingAdminService(zoneRepo, methodRepo, rateRepo);
  });

  it('rejects invalid formula on createRate', async () => {
    await expect(
      svc.createRate({ methodId: 'm1', calculationType: 'formula', price: '0', metaJson: { formula: 'process.exit()' } } as any),
    ).rejects.toThrow(BadRequestException);
  });

  it('accepts valid formula on createRate', async () => {
    await expect(
      svc.createRate({ methodId: 'm1', calculationType: 'formula', price: '0', metaJson: { formula: 'subtotal * 0.05' } } as any),
    ).resolves.toBeDefined();
  });
});