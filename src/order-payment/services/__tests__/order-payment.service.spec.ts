import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { OrderPaymentService } from '../../order-payment.service';
import { Order } from '../../../order/entities/order.entity';
import { OrderItem } from '../../../order/entities/order-item.entity';
import { OrderPayment } from '../../entities/order-payment.entity';
import { PaymentAllocation } from '../../entities/payment-allocation.entity';
import {
  OrderPaymentStatus,
  OrderPaymentType,
} from '../../order-payment.types';

describe('OrderPaymentService', () => {
  let service: OrderPaymentService;

  const orderRepo = { findOne: jest.fn(), createQueryBuilder: jest.fn() };
  const orderItemRepo = { findOne: jest.fn() };
  const paymentRepo = { find: jest.fn() };
  const allocationRepo: any = { createQueryBuilder: jest.fn() };

  const dataSource: any = {
    transaction: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        OrderPaymentService,
        { provide: DataSource, useValue: dataSource },
        { provide: getRepositoryToken(Order), useValue: orderRepo },
        { provide: getRepositoryToken(OrderItem), useValue: orderItemRepo },
        { provide: getRepositoryToken(OrderPayment), useValue: paymentRepo },
        {
          provide: getRepositoryToken(PaymentAllocation),
          useValue: allocationRepo,
        },
      ],
    }).compile();

    service = module.get<OrderPaymentService>(OrderPaymentService);
  });

  afterEach(() => jest.resetAllMocks());

  it('derives PARTIALLY_PAID from allocations', async () => {
    orderRepo.findOne.mockResolvedValue({
      id: 'ord1',
      currencyCode: 'KES',
      grandTotal: '150000.0000',
    } as any);

    const qb: any = {
      innerJoin: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      addSelect: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      groupBy: jest.fn().mockReturnThis(),
      getRawMany: jest
        .fn()
        .mockResolvedValue([
          { type: OrderPaymentType.CAPTURE, amount: '100000.0000' },
        ]),
    };
    allocationRepo.createQueryBuilder.mockReturnValue(qb);

    const summary = await service.getSummary('ord1');
    expect(summary.status).toBe('PARTIALLY_PAID');
    expect(summary.netPaidTotal).toBe('100000.0000');
  });

  it('derives PARTIALLY_REFUNDED when refundedTotal > 0 and still net positive', async () => {
    orderRepo.findOne.mockResolvedValue({
      id: 'ord1',
      currencyCode: 'KES',
      grandTotal: '150000.0000',
    } as any);

    const qb: any = {
      innerJoin: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      addSelect: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      groupBy: jest.fn().mockReturnThis(),
      getRawMany: jest.fn().mockResolvedValue([
        { type: OrderPaymentType.CAPTURE, amount: '150000.0000' },
        { type: OrderPaymentType.REFUND, amount: '10000.0000' },
      ]),
    };
    allocationRepo.createQueryBuilder.mockReturnValue(qb);

    const summary = await service.getSummary('ord1');
    expect(summary.status).toBe('PARTIALLY_REFUNDED');
    expect(summary.refundedTotal).toBe('10000.0000');
    expect(summary.netPaidTotal).toBe('140000.0000');
  });
});
