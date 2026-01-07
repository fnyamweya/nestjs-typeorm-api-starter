import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { EntityManager, Repository } from 'typeorm';
import { Order } from '../order/entities/order.entity';
import { OrderEvent } from './entities/order-event.entity';
import { OrderEventActorType, OrderEventTargetType } from './order-events.types';

export type OrderEventActor = {
  type: OrderEventActorType;
  id?: string;
  email?: string;
  name?: string;
  roleId?: string;
} | null;

export type LogOrderEventInput = {
  idempotencyKey: string;
  orderId: string;
  targetType: OrderEventTargetType;
  targetId: string;
  action: string;
  actor: OrderEventActor;
  orderItemId?: string | null;
  fulfillmentId?: string | null;
  packageId?: string | null;
  context?: Record<string, unknown>;
  nextAction?: string | null;
  nextActions?: string[];
};

function normalizeIdempotencyKey(key: string): string {
  const normalized = String(key || '').trim();
  if (!normalized) throw new BadRequestException('idempotencyKey is required');
  if (normalized.length > 255) throw new BadRequestException('idempotencyKey too long');
  return normalized;
}

function pgUniqueViolation(err: any): boolean {
  return Boolean(err?.code === '23505');
}

@Injectable()
export class OrderEventsService {
  constructor(
    @InjectRepository(Order)
    private readonly orderRepo: Repository<Order>,
    @InjectRepository(OrderEvent)
    private readonly eventRepo: Repository<OrderEvent>,
  ) {}

  private computeDefaultNext(action: string, context: Record<string, unknown>): { nextAction?: string; nextActions?: string[] } {
    const status = String((context as any)?.status ?? '').toUpperCase();
    if (action.startsWith('fulfillment.status.')) {
      if (status === 'PACKED') {
        return { nextAction: 'fulfillment.status.shipped', nextActions: ['fulfillment.status.shipped', 'fulfillment.status.cancelled'] };
      }
      if (status === 'SHIPPED') {
        return { nextAction: 'fulfillment.status.delivered', nextActions: ['fulfillment.status.delivered', 'fulfillment.status.cancelled'] };
      }
      if (status === 'DELIVERED') {
        return { nextAction: undefined, nextActions: [] };
      }
    }

    if (action === 'fulfillment.created') {
      return { nextAction: 'fulfillment.status.packed', nextActions: ['fulfillment.status.packed', 'fulfillment.status.shipped', 'fulfillment.status.cancelled'] };
    }

    return { nextAction: undefined, nextActions: [] };
  }

  async log(manager: EntityManager, input: LogOrderEventInput): Promise<OrderEvent> {
    const idempotencyKey = normalizeIdempotencyKey(input.idempotencyKey);
    const repo = manager.getRepository(OrderEvent);

    const existing = await repo.findOne({ where: { idempotencyKey } });
    if (existing) return existing;

    const order = await manager.getRepository(Order).findOne({ where: { id: input.orderId } });
    if (!order) throw new NotFoundException('Order not found');

    const previous = await repo.findOne({
      where: {
        orderId: input.orderId,
        targetType: input.targetType,
        targetId: input.targetId,
      },
      order: { createdAt: 'DESC' as any },
    } as any);

    const context = input.context ?? {};
    const computedNext = this.computeDefaultNext(input.action, context);
    const nextAction = input.nextAction !== undefined ? input.nextAction : computedNext.nextAction ?? null;
    const nextActions = input.nextActions !== undefined ? input.nextActions : computedNext.nextActions ?? [];

    const actorJson = input.actor
      ? {
          type: input.actor.type,
          id: input.actor.id,
          email: input.actor.email,
          name: input.actor.name,
          roleId: input.actor.roleId,
        }
      : {};

    const row = repo.create({
      orderId: input.orderId,
      targetType: input.targetType,
      targetId: input.targetId,
      orderItemId: input.orderItemId ?? null,
      fulfillmentId: input.fulfillmentId ?? null,
      packageId: input.packageId ?? null,
      action: input.action,
      idempotencyKey,
      actorType: input.actor?.type ?? null,
      actorId: input.actor?.id ?? null,
      actorJson,
      previousEventId: previous?.id ?? null,
      previousAction: previous?.action ?? null,
      previousCreatedAt: previous?.createdAt ?? null,
      nextAction: nextAction ?? null,
      nextActionsJson: nextActions ?? [],
      contextJson: context,
    });

    try {
      return await repo.save(row);
    } catch (err) {
      if (pgUniqueViolation(err)) {
        const after = await repo.findOne({ where: { idempotencyKey } });
        if (after) return after;
      }
      throw err;
    }
  }

  async listForOrder(orderId: string, opts?: { targetType?: OrderEventTargetType; targetId?: string }) {
    const order = await this.orderRepo.findOne({ where: { id: orderId } });
    if (!order) throw new NotFoundException('Order not found');

    const where: any = { orderId };
    if (opts?.targetType) where.targetType = opts.targetType;
    if (opts?.targetId) where.targetId = opts.targetId;

    const rows = await this.eventRepo.find({
      where,
      order: { createdAt: 'DESC' as any },
      take: 200,
    } as any);

    return rows.map((e) => ({
      id: e.id,
      orderId: e.orderId,
      targetType: e.targetType,
      targetId: e.targetId,
      orderItemId: e.orderItemId,
      fulfillmentId: e.fulfillmentId,
      packageId: e.packageId,
      action: e.action,
      idempotencyKey: e.idempotencyKey,
      actor: e.actorJson ?? {},
      previous: e.previousEventId
        ? {
            id: e.previousEventId,
            action: e.previousAction,
            createdAt: e.previousCreatedAt?.toISOString?.() ?? e.previousCreatedAt,
          }
        : null,
      next: {
        action: e.nextAction,
        actions: e.nextActionsJson ?? [],
      },
      context: e.contextJson ?? {},
      createdAt: e.createdAt?.toISOString?.() ?? e.createdAt,
    }));
  }
}
