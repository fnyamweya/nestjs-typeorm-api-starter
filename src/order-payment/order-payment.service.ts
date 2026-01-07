import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';
import { Order } from '../order/entities/order.entity';
import { OrderItem } from '../order/entities/order-item.entity';
import { OrderPayment } from './entities/order-payment.entity';
import { PaymentAllocation } from './entities/payment-allocation.entity';
import { AccountingService } from '../accounting/accounting.service';
import {
  DerivedOrderPaymentStatus,
  OrderPaymentStatus,
  OrderPaymentType,
  PaymentAllocationAppliesTo,
} from './order-payment.types';
import { CreateOrderPaymentDto } from './dto/create-order-payment.dto';
import { OrderPaymentSummaryDto } from './dto/order-payment-summary.dto';

function toMoneyString(amount: number): string {
  if (!Number.isFinite(amount)) throw new BadRequestException('Invalid amount');
  return amount.toFixed(4);
}

function normalizeCode(code: string): string {
  return String(code || '')
    .trim()
    .toUpperCase();
}

function sumMoney(values: Array<string | number>): number {
  return values.reduce<number>((acc, v) => acc + Number(v), 0);
}

function derivedStatus(opts: {
  grandTotal: number;
  netPaidTotal: number;
  refundedTotal: number;
}): DerivedOrderPaymentStatus {
  const { grandTotal, netPaidTotal, refundedTotal } = opts;
  if (refundedTotal > 0) {
    if (netPaidTotal <= 0) return DerivedOrderPaymentStatus.REFUNDED;
    return DerivedOrderPaymentStatus.PARTIALLY_REFUNDED;
  }

  if (netPaidTotal <= 0) return DerivedOrderPaymentStatus.PENDING;
  if (netPaidTotal < grandTotal)
    return DerivedOrderPaymentStatus.PARTIALLY_PAID;
  if (netPaidTotal === grandTotal) return DerivedOrderPaymentStatus.PAID;
  return DerivedOrderPaymentStatus.OVERPAID;
}

@Injectable()
export class OrderPaymentService {
  constructor(
    private readonly dataSource: DataSource,
    private readonly accountingService: AccountingService,
    @InjectRepository(Order)
    private readonly orderRepo: Repository<Order>,
    @InjectRepository(OrderItem)
    private readonly orderItemRepo: Repository<OrderItem>,
    @InjectRepository(OrderPayment)
    private readonly paymentRepo: Repository<OrderPayment>,
    @InjectRepository(PaymentAllocation)
    private readonly allocationRepo: Repository<PaymentAllocation>,
  ) {}

  private assertAmountAllowed(type: OrderPaymentType, amount: number): void {
    if (!Number.isFinite(amount) || amount === 0) {
      throw new BadRequestException('amount must be a non-zero number');
    }
    if (type !== OrderPaymentType.ADJUSTMENT && amount < 0) {
      throw new BadRequestException(
        'amount must be positive (negative allowed only for ADJUSTMENT)',
      );
    }
  }

  private paymentSign(type: OrderPaymentType, amount: number): number {
    if (type === OrderPaymentType.CAPTURE) return 1;
    if (type === OrderPaymentType.ADJUSTMENT) return amount >= 0 ? 1 : -1;
    if (type === OrderPaymentType.REFUND) return -1;
    if (type === OrderPaymentType.REVERSAL) return -1;
    return 0;
  }

  async listForOrder(orderId: string): Promise<OrderPayment[]> {
    const order = await this.orderRepo.findOne({ where: { id: orderId } });
    if (!order) throw new NotFoundException('Order not found');

    return this.paymentRepo.find({
      where: { orderId },
      order: { createdAt: 'DESC' as any },
      relations: { allocations: true } as any,
    });
  }

  async createForOrder(
    orderId: string,
    payload: CreateOrderPaymentDto,
  ): Promise<OrderPayment> {
    const currency = normalizeCode(payload.currency);
    const provider = String(payload.provider || '').trim();
    const method = String(payload.method || '').trim();

    if (!provider) throw new BadRequestException('provider is required');
    if (!method) throw new BadRequestException('method is required');
    if (!currency) throw new BadRequestException('currency is required');
    this.assertAmountAllowed(payload.type, payload.amount);

    return this.dataSource.transaction(async (manager) => {
      const orderRepository = manager.getRepository(Order);
      const paymentRepository = manager.getRepository(OrderPayment);
      const allocationRepository = manager.getRepository(PaymentAllocation);
      const orderItemRepository = manager.getRepository(OrderItem);

      const order = await orderRepository
        .createQueryBuilder('o')
        .where('o.id = :id', { id: orderId })
        .setLock('pessimistic_write')
        .getOne();

      if (!order) throw new NotFoundException('Order not found');

      if (normalizeCode(order.currencyCode) !== currency) {
        throw new BadRequestException(
          'Payment currency must match order currency',
        );
      }

      const payment = paymentRepository.create({
        orderId: order.id,
        type: payload.type,
        status: payload.status,
        provider: provider,
        method: method,
        amount: toMoneyString(payload.amount),
        currencyCode: currency,
        externalRef: payload.externalRef?.trim() || undefined,
        initiatedAt: payload.initiatedAt
          ? new Date(payload.initiatedAt)
          : undefined,
        confirmedAt: payload.confirmedAt
          ? new Date(payload.confirmedAt)
          : undefined,
        metaJson: payload.metaJson ?? {},
      });

      const savedPayment = await paymentRepository.save(payment);

      const allocations = payload.allocations?.length
        ? payload.allocations
        : [
            {
              appliesTo: PaymentAllocationAppliesTo.ORDER,
              amount: payload.amount,
              currency: currency,
              metaJson: {},
            },
          ];

      const normalizedAllocations = allocations.map((a) => ({
        appliesTo: a.appliesTo,
        orderItemId: a.orderItemId,
        amount: a.amount,
        currency: normalizeCode(a.currency),
        metaJson: a.metaJson ?? {},
      }));

      const allocTotal = sumMoney(normalizedAllocations.map((a) => a.amount));
      if (Number(allocTotal.toFixed(4)) !== Number(payload.amount.toFixed(4))) {
        throw new BadRequestException(
          'Sum of allocation amounts must equal payment amount',
        );
      }

      for (const a of normalizedAllocations) {
        if (!Number.isFinite(a.amount) || a.amount === 0) {
          throw new BadRequestException(
            'Allocation amount must be a non-zero number',
          );
        }
        if (payload.type !== OrderPaymentType.ADJUSTMENT && a.amount < 0) {
          throw new BadRequestException(
            'Allocation amount must be positive (negative allowed only for ADJUSTMENT)',
          );
        }
        if (a.currency !== currency) {
          throw new BadRequestException(
            'Allocation currency must match payment currency',
          );
        }
        if (a.appliesTo === PaymentAllocationAppliesTo.ORDER) {
          if (a.orderItemId)
            throw new BadRequestException(
              'orderItemId is not allowed when appliesTo=ORDER',
            );
        }
        if (a.appliesTo === PaymentAllocationAppliesTo.ORDER_ITEM) {
          if (!a.orderItemId)
            throw new BadRequestException(
              'orderItemId is required when appliesTo=ORDER_ITEM',
            );
          const item = await orderItemRepository.findOne({
            where: { id: a.orderItemId },
          });
          if (!item || item.orderId !== order.id) {
            throw new BadRequestException(
              'orderItemId must belong to the order',
            );
          }
        }
      }

      const allocationEntities = normalizedAllocations.map((a) =>
        allocationRepository.create({
          paymentId: savedPayment.id,
          orderId: order.id,
          appliesTo: a.appliesTo,
          orderItemId: a.orderItemId ?? null,
          amount: toMoneyString(a.amount),
          currencyCode: currency,
          metaJson: a.metaJson,
        }),
      );

      await allocationRepository.save(allocationEntities);

      // Double-entry posting: only post SUCCEEDED transactions.
      // PENDING/FAILED/CANCELLED are operational events but should not hit the ledger.
      if (payload.status === OrderPaymentStatus.SUCCEEDED) {
        await this.accountingService.postForOrderPayment(manager, {
          paymentId: savedPayment.id,
          orderId: order.id,
          type: payload.type,
          provider: provider,
          method: method,
          amount: payload.amount,
          currency: currency,
          postedAt: payload.confirmedAt
            ? new Date(payload.confirmedAt)
            : payload.initiatedAt
              ? new Date(payload.initiatedAt)
              : new Date(),
        });
      }

      return paymentRepository.findOneOrFail({
        where: { id: savedPayment.id },
        relations: { allocations: true } as any,
      });
    });
  }

  async getSummary(orderId: string): Promise<OrderPaymentSummaryDto> {
    const order = await this.orderRepo.findOne({ where: { id: orderId } });
    if (!order) throw new NotFoundException('Order not found');

    // We use allocations (not payment.amount) so partial payments remain bulletproof.
    const rows = await this.allocationRepo
      .createQueryBuilder('a')
      .innerJoin('a.payment', 'p')
      .select('p.type', 'type')
      .addSelect('SUM(a.amount)', 'amount')
      .where('a.order_id = :orderId', { orderId })
      .andWhere('p.status = :status', { status: OrderPaymentStatus.SUCCEEDED })
      .groupBy('p.type')
      .getRawMany<{ type: OrderPaymentType; amount: string }>();

    const byType = new Map<OrderPaymentType, number>();
    for (const r of rows) {
      byType.set(r.type, Number(r.amount ?? 0));
    }

    const capturedTotal = byType.get(OrderPaymentType.CAPTURE) ?? 0;
    const adjustedTotal = byType.get(OrderPaymentType.ADJUSTMENT) ?? 0;
    const reversedTotal = byType.get(OrderPaymentType.REVERSAL) ?? 0;
    const refundedTotal = byType.get(OrderPaymentType.REFUND) ?? 0;

    const netPaidTotal =
      capturedTotal + adjustedTotal - reversedTotal - refundedTotal;
    const grandTotal = Number(order.grandTotal ?? 0);
    const status = derivedStatus({ grandTotal, netPaidTotal, refundedTotal });

    return {
      orderId,
      currency: normalizeCode(order.currencyCode),
      grandTotal: toMoneyString(grandTotal),
      capturedTotal: toMoneyString(capturedTotal),
      adjustedTotal: toMoneyString(adjustedTotal),
      reversedTotal: toMoneyString(reversedTotal),
      refundedTotal: toMoneyString(refundedTotal),
      netPaidTotal: toMoneyString(netPaidTotal),
      status,
    };
  }

  /**
   * Efficiently compute payment summary status for multiple orders without N+1 queries.
   * Uses allocations grouped by order_id + payment.type for SUCCEEDED payments only.
   */
  async getStatusMapForOrders(
    orders: Array<{ id: string; grandTotal: string }>,
  ): Promise<Record<string, DerivedOrderPaymentStatus>> {
    const ids = orders.map((o) => o.id).filter(Boolean);
    if (ids.length === 0) return {};

    const rows = await this.allocationRepo
      .createQueryBuilder('a')
      .innerJoin('a.payment', 'p')
      .select('a.order_id', 'orderId')
      .addSelect('p.type', 'type')
      .addSelect('SUM(a.amount)', 'amount')
      .where('a.order_id IN (:...ids)', { ids })
      .andWhere('p.status = :status', { status: OrderPaymentStatus.SUCCEEDED })
      .groupBy('a.order_id')
      .addGroupBy('p.type')
      .getRawMany<{
        orderId: string;
        type: OrderPaymentType;
        amount: string;
      }>();

    const totalsByOrder = new Map<
      string,
      {
        captured: number;
        adjusted: number;
        reversed: number;
        refunded: number;
      }
    >();

    for (const id of ids) {
      totalsByOrder.set(id, {
        captured: 0,
        adjusted: 0,
        reversed: 0,
        refunded: 0,
      });
    }

    for (const r of rows) {
      const bucket = totalsByOrder.get(r.orderId);
      if (!bucket) continue;
      const amount = Number(r.amount ?? 0);
      if (r.type === OrderPaymentType.CAPTURE) bucket.captured += amount;
      else if (r.type === OrderPaymentType.ADJUSTMENT)
        bucket.adjusted += amount;
      else if (r.type === OrderPaymentType.REVERSAL) bucket.reversed += amount;
      else if (r.type === OrderPaymentType.REFUND) bucket.refunded += amount;
    }

    const result: Record<string, DerivedOrderPaymentStatus> = {};
    for (const order of orders) {
      const t = totalsByOrder.get(order.id) ?? {
        captured: 0,
        adjusted: 0,
        reversed: 0,
        refunded: 0,
      };
      const netPaidTotal = t.captured + t.adjusted - t.reversed - t.refunded;
      const grandTotal = Number(order.grandTotal ?? 0);
      result[order.id] = derivedStatus({
        grandTotal,
        netPaidTotal,
        refundedTotal: t.refunded,
      });
    }

    return result;
  }

  async getSummaryMapForOrders(
    orders: Array<{ id: string; grandTotal: string }>,
  ): Promise<
    Record<
      string,
      {
        capturedTotal: string;
        adjustedTotal: string;
        reversedTotal: string;
        refundedTotal: string;
        netPaidTotal: string;
        status: DerivedOrderPaymentStatus;
      }
    >
  > {
    const ids = orders.map((o) => o.id).filter(Boolean);
    if (ids.length === 0) return {};

    const rows = await this.allocationRepo
      .createQueryBuilder('a')
      .innerJoin('a.payment', 'p')
      .select('a.order_id', 'orderId')
      .addSelect('p.type', 'type')
      .addSelect('SUM(a.amount)', 'amount')
      .where('a.order_id IN (:...ids)', { ids })
      .andWhere('p.status = :status', { status: OrderPaymentStatus.SUCCEEDED })
      .groupBy('a.order_id')
      .addGroupBy('p.type')
      .getRawMany<{ orderId: string; type: OrderPaymentType; amount: string }>();

    const totalsByOrder = new Map<
      string,
      {
        captured: number;
        adjusted: number;
        reversed: number;
        refunded: number;
      }
    >();

    for (const id of ids) {
      totalsByOrder.set(id, { captured: 0, adjusted: 0, reversed: 0, refunded: 0 });
    }

    for (const r of rows) {
      const bucket = totalsByOrder.get(r.orderId);
      if (!bucket) continue;
      const amount = Number(r.amount ?? 0);
      if (r.type === OrderPaymentType.CAPTURE) bucket.captured += amount;
      else if (r.type === OrderPaymentType.ADJUSTMENT) bucket.adjusted += amount;
      else if (r.type === OrderPaymentType.REVERSAL) bucket.reversed += amount;
      else if (r.type === OrderPaymentType.REFUND) bucket.refunded += amount;
    }

    const result: Record<
      string,
      {
        capturedTotal: string;
        adjustedTotal: string;
        reversedTotal: string;
        refundedTotal: string;
        netPaidTotal: string;
        status: DerivedOrderPaymentStatus;
      }
    > = {};

    for (const order of orders) {
      const t = totalsByOrder.get(order.id) ?? { captured: 0, adjusted: 0, reversed: 0, refunded: 0 };
      const netPaidTotal = t.captured + t.adjusted - t.reversed - t.refunded;
      const grandTotal = Number(order.grandTotal ?? 0);
      result[order.id] = {
        capturedTotal: toMoneyString(t.captured),
        adjustedTotal: toMoneyString(t.adjusted),
        reversedTotal: toMoneyString(t.reversed),
        refundedTotal: toMoneyString(t.refunded),
        netPaidTotal: toMoneyString(netPaidTotal),
        status: derivedStatus({ grandTotal, netPaidTotal, refundedTotal: t.refunded }),
      };
    }

    return result;
  }
}
