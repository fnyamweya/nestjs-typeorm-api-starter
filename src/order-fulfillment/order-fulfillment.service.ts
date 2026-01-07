import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';
import { Order, FulfillmentStatus as OrderFulfillmentAggregateStatus } from '../order/entities/order.entity';
import { OrderItem } from '../order/entities/order-item.entity';
import { OrderShippingAddress } from '../order/entities/order-shipping-address.entity';
import { ShippingMethod } from '../shipping/entities/shipping-method.entity';
import { OrderFulfillment } from './entities/order-fulfillment.entity';
import { FulfillmentPackage } from './entities/fulfillment-package.entity';
import { FulfillmentItem } from './entities/fulfillment-item.entity';
import { PackageItem } from './entities/package-item.entity';
import { CreateOrderFulfillmentDto } from './dto/create-fulfillment.dto';
import { UpdateOrderFulfillmentDto } from './dto/update-fulfillment.dto';
import { OrderFulfillmentStatus } from './order-fulfillment.types';
import { OrderEventsService, OrderEventActor } from '../order-events/order-events.service';
import { OrderEventTargetType } from '../order-events/order-events.types';
import { AccountingService } from '../accounting/accounting.service';

function toMoneyString(amount: number): string {
  if (!Number.isFinite(amount)) throw new BadRequestException('Invalid amount');
  return amount.toFixed(4);
}

function normalizeCode(code: string): string {
  return String(code || '').trim().toUpperCase();
}

@Injectable()
export class OrderFulfillmentService {
  constructor(
    private readonly dataSource: DataSource,
    private readonly orderEvents: OrderEventsService,
    private readonly accountingService: AccountingService,
    @InjectRepository(Order)
    private readonly orderRepo: Repository<Order>,
    @InjectRepository(OrderItem)
    private readonly orderItemRepo: Repository<OrderItem>,
    @InjectRepository(OrderShippingAddress)
    private readonly orderShippingAddressRepo: Repository<OrderShippingAddress>,
    @InjectRepository(ShippingMethod)
    private readonly shippingMethodRepo: Repository<ShippingMethod>,
    @InjectRepository(OrderFulfillment)
    private readonly fulfillmentRepo: Repository<OrderFulfillment>,
    @InjectRepository(FulfillmentPackage)
    private readonly packageRepo: Repository<FulfillmentPackage>,
    @InjectRepository(FulfillmentItem)
    private readonly fulfillmentItemRepo: Repository<FulfillmentItem>,
    @InjectRepository(PackageItem)
    private readonly packageItemRepo: Repository<PackageItem>,
  ) {}

  private async getAlreadyFulfilledQtyMapForRepo(
    fulfillmentItemRepo: Repository<FulfillmentItem>,
    orderId: string,
  ): Promise<Map<string, number>> {
    const rows = await fulfillmentItemRepo
      .createQueryBuilder('fi')
      .innerJoin(OrderFulfillment, 'f', 'f.id = fi.fulfillment_id')
      .select('fi.order_item_id', 'orderItemId')
      .addSelect('SUM(fi.quantity)', 'qty')
      .where('f.order_id = :orderId', { orderId })
      .andWhere('f.status != :cancelled', { cancelled: OrderFulfillmentStatus.CANCELLED })
      .groupBy('fi.order_item_id')
      .getRawMany<{ orderItemId: string; qty: string }>();

    const map = new Map<string, number>();
    for (const r of rows) map.set(r.orderItemId, Number(r.qty ?? 0));
    return map;
  }

  private async recomputeOrderFulfillmentStatus(orderId: string, manager: DataSource['manager']): Promise<void> {
    const orderRepository = manager.getRepository(Order);
    const orderItemRepository = manager.getRepository(OrderItem);
    const fulfillmentItemRepository = manager.getRepository(FulfillmentItem);

    const order = await orderRepository.findOne({ where: { id: orderId } });
    if (!order) return;

    const items = await orderItemRepository.find({ where: { orderId } });
    const shippable = items.filter((i) => i.requiresShipping);
    if (shippable.length === 0) {
      order.fulfillmentStatus = OrderFulfillmentAggregateStatus.FULFILLED;
      await orderRepository.save(order);
      return;
    }

    const rows = await fulfillmentItemRepository
      .createQueryBuilder('fi')
      .innerJoin(OrderFulfillment, 'f', 'f.id = fi.fulfillment_id')
      .select('fi.order_item_id', 'orderItemId')
      .addSelect('SUM(fi.quantity)', 'qty')
      .where('f.order_id = :orderId', { orderId })
      .andWhere('f.status != :cancelled', { cancelled: OrderFulfillmentStatus.CANCELLED })
      .groupBy('fi.order_item_id')
      .getRawMany<{ orderItemId: string; qty: string }>();

    const fulfilledMap = new Map<string, number>();
    for (const r of rows) fulfilledMap.set(r.orderItemId, Number(r.qty ?? 0));

    let any = false;
    let all = true;
    for (const item of shippable) {
      const fQty = fulfilledMap.get(item.id) ?? 0;
      if (fQty > 0) any = true;
      if (fQty < item.quantity) all = false;
      // keep item-level status aligned
      (item as any).fulfillmentStatus = fQty <= 0 ? 'unfulfilled' : fQty < item.quantity ? 'partial' : 'fulfilled';
    }

    await orderItemRepository.save(shippable as any);

    order.fulfillmentStatus = !any
      ? OrderFulfillmentAggregateStatus.UNFULFILLED
      : all
        ? OrderFulfillmentAggregateStatus.FULFILLED
        : OrderFulfillmentAggregateStatus.PARTIAL;

    await orderRepository.save(order);
  }

  private buildPublicFulfillmentShape(f: OrderFulfillment) {
    return {
      id: f.id,
      orderId: f.orderId,
      status: f.status,
      shippingMethod: Object.keys(f.shippingMethodSnapshotJson || {}).length
        ? f.shippingMethodSnapshotJson
        : f.shippingMethodId
          ? { id: f.shippingMethodId }
          : null,
      tracking: {
        trackingNumber: f.trackingNumber,
        trackingUrl: f.trackingUrl,
      },
      origin: {
        locationId: f.originLocationId,
        name: f.originName,
      },
      destination: f.destinationJson ?? {},
      packages:
        f.packages?.map((p) => ({
          packageId: p.id,
          weight:
            p.weightValue && p.weightUnit
              ? { value: Number(p.weightValue), unit: p.weightUnit }
              : undefined,
          dimensions:
            p.dimLength && p.dimWidth && p.dimHeight && p.dimUnit
              ? {
                  length: Number(p.dimLength),
                  width: Number(p.dimWidth),
                  height: Number(p.dimHeight),
                  unit: p.dimUnit,
                }
              : undefined,
          trackingNumber: p.trackingNumber,
          items:
            p.packageItems?.map((pi) => ({
              id: pi.id,
              packageId: p.id,
              orderItemId: pi.orderItemId,
              quantity: pi.quantity,
            })) ?? [],
        })) ?? [],
      fulfillmentItems:
        f.fulfillmentItems?.map((i) => ({
          orderItemId: i.orderItemId,
          quantity: i.quantity,
        })) ?? [],
      cost: {
        currency: f.currencyCode,
        shippingAmount: Number(f.shippingAmount),
        insuranceAmount: Number(f.insuranceAmount),
      },
      timestamps: {
        packedAt: f.packedAt ? f.packedAt.toISOString() : null,
        shippedAt: f.shippedAt ? f.shippedAt.toISOString() : null,
        deliveredAt: f.deliveredAt ? f.deliveredAt.toISOString() : null,
      },
      metaJson: f.metaJson ?? {},
      createdAt: f.createdAt?.toISOString?.() ?? f.createdAt,
      updatedAt: f.updatedAt?.toISOString?.() ?? f.updatedAt,
    };
  }

  private statusKey(status: string): string {
    return String(status || '').trim().toLowerCase();
  }

  async listForOrder(orderId: string) {
    const order = await this.orderRepo.findOne({ where: { id: orderId } });
    if (!order) throw new NotFoundException('Order not found');

    const fulfillments = await this.fulfillmentRepo.find({
      where: { orderId },
      order: { createdAt: 'DESC' as any },
      relations: {
        packages: { packageItems: true } as any,
        fulfillmentItems: true,
      } as any,
    });

    return fulfillments.map((f) => this.buildPublicFulfillmentShape(f));
  }

  async getForOrder(orderId: string, fulfillmentId: string) {
    const f = await this.fulfillmentRepo.findOne({
      where: { id: fulfillmentId, orderId },
      relations: {
        packages: { packageItems: true } as any,
        fulfillmentItems: true,
      } as any,
    } as any);
    if (!f) throw new NotFoundException('Fulfillment not found');
    return this.buildPublicFulfillmentShape(f);
  }

  async createForOrder(
    orderId: string,
    payload: CreateOrderFulfillmentDto,
    actor: OrderEventActor = null,
  ) {
    if (!payload.packages?.length) throw new BadRequestException('packages is required');

    return this.dataSource.transaction(async (manager) => {
      const orderRepository = manager.getRepository(Order);
      const orderItemRepository = manager.getRepository(OrderItem);
      const shippingAddressRepository = manager.getRepository(OrderShippingAddress);
      const shippingMethodRepository = manager.getRepository(ShippingMethod);
      const fulfillmentRepository = manager.getRepository(OrderFulfillment);
      const packageRepository = manager.getRepository(FulfillmentPackage);
      const fulfillmentItemRepository = manager.getRepository(FulfillmentItem);
      const packageItemRepository = manager.getRepository(PackageItem);

      const order = await orderRepository
        .createQueryBuilder('o')
        .where('o.id = :id', { id: orderId })
        .setLock('pessimistic_write')
        .getOne();
      if (!order) throw new NotFoundException('Order not found');

      const items = await orderItemRepository.find({ where: { orderId } });
      const itemsById = new Map(items.map((i) => [i.id, i] as const));

      const destinationSnapshot =
        payload.destination ??
        (await shippingAddressRepository.findOne({ where: { orderId } }).then((a) => {
          if (!a) return {};
          return {
            firstName: a.firstName,
            lastName: a.lastName,
            phone: a.phone,
            countryCode: a.countryCode,
            locationId: a.locationId,
            fieldsJson: a.fieldsJson,
          };
        }));

      const currency = normalizeCode(payload.cost?.currency ?? order.currencyCode);
      if (currency !== normalizeCode(order.currencyCode)) {
        throw new BadRequestException('Fulfillment currency must match order currency');
      }

      let shippingMethodSnapshot: Record<string, unknown> = {};
      let shippingMethodId: string | null = payload.shippingMethodId ?? null;
      if (shippingMethodId) {
        const method = await shippingMethodRepository.findOne({ where: { id: shippingMethodId } });
        if (!method) throw new BadRequestException('Invalid shippingMethodId');
        shippingMethodSnapshot = {
          id: method.id,
          code: method.code,
          displayName: method.displayName,
          provider: method.provider,
        };
      }

      // Derive quantities from packages
      const derivedMap = new Map<string, number>();
      for (const pkg of payload.packages) {
        if (!pkg.items?.length) throw new BadRequestException('Each package must include items');
        for (const it of pkg.items) {
          const orderItem = itemsById.get(it.orderItemId);
          if (!orderItem) throw new BadRequestException('PackageItem.orderItemId must belong to the order');
          if (it.quantity <= 0) throw new BadRequestException('PackageItem.quantity must be > 0');
          derivedMap.set(it.orderItemId, (derivedMap.get(it.orderItemId) ?? 0) + it.quantity);
        }
      }
      if (derivedMap.size === 0) throw new BadRequestException('packages.items must allocate at least one item');

      // If fulfillmentItems were provided, ensure they match derived totals.
      if (payload.fulfillmentItems?.length) {
        const provided = new Map<string, number>();
        for (const fi of payload.fulfillmentItems) {
          if (!itemsById.get(fi.orderItemId)) {
            throw new BadRequestException('FulfillmentItem.orderItemId must belong to the order');
          }
          provided.set(fi.orderItemId, (provided.get(fi.orderItemId) ?? 0) + fi.quantity);
        }
        const keys = new Set([...Array.from(provided.keys()), ...Array.from(derivedMap.keys())]);
        for (const k of keys) {
          if ((provided.get(k) ?? 0) !== (derivedMap.get(k) ?? 0)) {
            throw new BadRequestException('fulfillmentItems must equal sum(packages.items) by orderItemId');
          }
        }
      }

      // Prevent over-fulfilling
      const alreadyMap = await this.getAlreadyFulfilledQtyMapForRepo(fulfillmentItemRepository, orderId);
      for (const [orderItemId, qty] of derivedMap.entries()) {
        const item = itemsById.get(orderItemId);
        if (!item) continue;
        const already = alreadyMap.get(orderItemId) ?? 0;
        const remaining = item.quantity - already;
        if (qty > remaining) {
          throw new BadRequestException('Cannot fulfill more than remaining quantity for an item');
        }
      }

      const fulfillment = fulfillmentRepository.create({
        orderId,
        status: payload.status,
        shippingMethodId,
        shippingMethodSnapshotJson: shippingMethodSnapshot,
        trackingNumber: payload.tracking?.trackingNumber,
        trackingUrl: payload.tracking?.trackingUrl,
        originLocationId: payload.origin?.locationId ?? null,
        originName: payload.origin?.name,
        destinationJson: destinationSnapshot ?? {},
        currencyCode: currency,
        shippingAmount: toMoneyString(payload.cost?.shippingAmount ?? 0),
        insuranceAmount: toMoneyString(payload.cost?.insuranceAmount ?? 0),
        packedAt: payload.timestamps?.packedAt ? new Date(payload.timestamps.packedAt) : undefined,
        shippedAt: payload.timestamps?.shippedAt ? new Date(payload.timestamps.shippedAt) : undefined,
        deliveredAt: payload.timestamps?.deliveredAt ? new Date(payload.timestamps.deliveredAt) : undefined,
        metaJson: payload.metaJson ?? {},
      });

      const saved = await fulfillmentRepository.save(fulfillment);

      // Events: fulfillment created
      await this.orderEvents.log(manager, {
        idempotencyKey: `fulfillment:${saved.id}:created`,
        orderId,
        targetType: OrderEventTargetType.FULFILLMENT,
        targetId: saved.id,
        action: 'fulfillment.created',
        actor,
        fulfillmentId: saved.id,
        context: {
          fulfillmentId: saved.id,
          orderId,
          status: saved.status,
        },
      });

      await this.orderEvents.log(manager, {
        idempotencyKey: `order:${orderId}:fulfillment:${saved.id}:created`,
        orderId,
        targetType: OrderEventTargetType.ORDER,
        targetId: orderId,
        action: 'order.fulfillment.created',
        actor,
        fulfillmentId: saved.id,
        context: {
          orderId,
          fulfillmentId: saved.id,
          status: saved.status,
        },
      });

      // Packages
      const savedPackages: FulfillmentPackage[] = [];
      for (const pkg of payload.packages) {
        const p = packageRepository.create({
          fulfillmentId: saved.id,
          weightValue: pkg.weight ? String(pkg.weight.value.toFixed(4)) : undefined,
          weightUnit: pkg.weight?.unit,
          dimLength: pkg.dimensions ? String(pkg.dimensions.length.toFixed(4)) : undefined,
          dimWidth: pkg.dimensions ? String(pkg.dimensions.width.toFixed(4)) : undefined,
          dimHeight: pkg.dimensions ? String(pkg.dimensions.height.toFixed(4)) : undefined,
          dimUnit: pkg.dimensions?.unit,
          trackingNumber: pkg.trackingNumber,
          metaJson: pkg.metaJson ?? {},
        });
        const savedPkg = await packageRepository.save(p);
        savedPackages.push(savedPkg);

        await this.orderEvents.log(manager, {
          idempotencyKey: `package:${savedPkg.id}:created`,
          orderId,
          targetType: OrderEventTargetType.PACKAGE,
          targetId: savedPkg.id,
          action: 'package.created',
          actor,
          fulfillmentId: saved.id,
          packageId: savedPkg.id,
          context: {
            orderId,
            fulfillmentId: saved.id,
            packageId: savedPkg.id,
            trackingNumber: savedPkg.trackingNumber,
            weight: savedPkg.weightValue && savedPkg.weightUnit ? { value: savedPkg.weightValue, unit: savedPkg.weightUnit } : null,
            dimensions:
              savedPkg.dimLength && savedPkg.dimWidth && savedPkg.dimHeight && savedPkg.dimUnit
                ? { length: savedPkg.dimLength, width: savedPkg.dimWidth, height: savedPkg.dimHeight, unit: savedPkg.dimUnit }
                : null,
          },
        });
      }

      // Package items (join table) - dedupe orderItemId per package to avoid unique constraint surprises
      for (let idx = 0; idx < payload.packages.length; idx++) {
        const reqPkg = payload.packages[idx];
        const dbPkg = savedPackages[idx];

        const perPackage = new Map<string, number>();
        for (const it of reqPkg.items) {
          perPackage.set(it.orderItemId, (perPackage.get(it.orderItemId) ?? 0) + it.quantity);
        }

        for (const [orderItemId, quantity] of perPackage.entries()) {
          await packageItemRepository.save(
            packageItemRepository.create({
              packageId: dbPkg.id,
              orderItemId,
              quantity,
            }),
          );

          await this.orderEvents.log(manager, {
            idempotencyKey: `order_item:${orderItemId}:fulfillment:${saved.id}:allocated`,
            orderId,
            targetType: OrderEventTargetType.ORDER_ITEM,
            targetId: orderItemId,
            action: 'order_item.fulfillment.allocated',
            actor,
            orderItemId,
            fulfillmentId: saved.id,
            packageId: dbPkg.id,
            context: {
              orderId,
              orderItemId,
              fulfillmentId: saved.id,
              packageId: dbPkg.id,
              quantity,
            },
          });

          await this.orderEvents.log(manager, {
            idempotencyKey: `package:${dbPkg.id}:order_item:${orderItemId}:allocated`,
            orderId,
            targetType: OrderEventTargetType.PACKAGE,
            targetId: dbPkg.id,
            action: 'package.order_item.allocated',
            actor,
            orderItemId,
            fulfillmentId: saved.id,
            packageId: dbPkg.id,
            context: {
              orderId,
              orderItemId,
              fulfillmentId: saved.id,
              packageId: dbPkg.id,
              quantity,
            },
          });
        }
      }

      // Fulfillment items
      for (const [orderItemId, qty] of derivedMap.entries()) {
        await fulfillmentItemRepository.save(
          fulfillmentItemRepository.create({
            fulfillmentId: saved.id,
            orderItemId,
            quantity: qty,
          }),
        );
      }

      // Event: fulfillment status (idempotent)
      await this.orderEvents.log(manager, {
        idempotencyKey: `fulfillment:${saved.id}:${this.statusKey(saved.status)}`,
        orderId,
        targetType: OrderEventTargetType.FULFILLMENT,
        targetId: saved.id,
        action: `fulfillment.status.${this.statusKey(saved.status)}`,
        actor,
        fulfillmentId: saved.id,
        context: {
          orderId,
          fulfillmentId: saved.id,
          status: saved.status,
        },
      });

      await this.orderEvents.log(manager, {
        idempotencyKey: `order:${orderId}:fulfillment:${saved.id}:${this.statusKey(saved.status)}`,
        orderId,
        targetType: OrderEventTargetType.ORDER,
        targetId: orderId,
        action: `order.fulfillment.status.${this.statusKey(saved.status)}`,
        actor,
        fulfillmentId: saved.id,
        context: {
          orderId,
          fulfillmentId: saved.id,
          status: saved.status,
        },
      });

      await this.recomputeOrderFulfillmentStatus(orderId, manager);

      const hydrated = await fulfillmentRepository.findOneOrFail({
        where: { id: saved.id },
        relations: { packages: { packageItems: true } as any, fulfillmentItems: true } as any,
      });

      // Event: package mirrors fulfillment status (optional but ensures package-level step tracking)
      for (const pkg of savedPackages) {
        await this.orderEvents.log(manager, {
          idempotencyKey: `package:${pkg.id}:fulfillment:${saved.id}:${this.statusKey(saved.status)}`,
          orderId,
          targetType: OrderEventTargetType.PACKAGE,
          targetId: pkg.id,
          action: `package.fulfillment.status.${this.statusKey(saved.status)}`,
          actor,
          fulfillmentId: saved.id,
          packageId: pkg.id,
          context: {
            orderId,
            fulfillmentId: saved.id,
            packageId: pkg.id,
            status: saved.status,
          },
        });
      }

      return this.buildPublicFulfillmentShape(hydrated);
    });
  }

  async updateForOrder(
    orderId: string,
    fulfillmentId: string,
    payload: UpdateOrderFulfillmentDto,
    actor: OrderEventActor = null,
  ) {
    return this.dataSource.transaction(async (manager) => {
      const fulfillmentRepository = manager.getRepository(OrderFulfillment);
      const shippingMethodRepository = manager.getRepository(ShippingMethod);
      const orderRepository = manager.getRepository(Order);
      const orderItemRepository = manager.getRepository(OrderItem);

      const f = await fulfillmentRepository.findOne({
        where: { id: fulfillmentId, orderId },
        relations: { packages: { packageItems: true } as any, fulfillmentItems: true } as any,
      } as any);
      if (!f) throw new NotFoundException('Fulfillment not found');

      const prevStatus = f.status;

      if (payload.status) f.status = payload.status;
      if (payload.tracking) {
        if (payload.tracking.trackingNumber !== undefined) f.trackingNumber = payload.tracking.trackingNumber;
        if (payload.tracking.trackingUrl !== undefined) f.trackingUrl = payload.tracking.trackingUrl;
      }
      if (payload.timestamps) {
        if (payload.timestamps.packedAt !== undefined) f.packedAt = payload.timestamps.packedAt ? new Date(payload.timestamps.packedAt) : undefined;
        if (payload.timestamps.shippedAt !== undefined) f.shippedAt = payload.timestamps.shippedAt ? new Date(payload.timestamps.shippedAt) : undefined;
        if (payload.timestamps.deliveredAt !== undefined)
          f.deliveredAt = payload.timestamps.deliveredAt ? new Date(payload.timestamps.deliveredAt) : undefined;
      }
      if (payload.metaJson) f.metaJson = { ...(f.metaJson ?? {}), ...payload.metaJson };

      if (payload.shippingMethodId !== undefined) {
        if (!payload.shippingMethodId) {
          f.shippingMethodId = null;
          f.shippingMethodSnapshotJson = {};
        } else {
          const method = await shippingMethodRepository.findOne({ where: { id: payload.shippingMethodId } });
          if (!method) throw new BadRequestException('Invalid shippingMethodId');
          f.shippingMethodId = method.id;
          f.shippingMethodSnapshotJson = {
            id: method.id,
            code: method.code,
            displayName: method.displayName,
            provider: method.provider,
          };
        }
      }

      await fulfillmentRepository.save(f);

      // Revenue recognition: when fulfillment is delivered, recognize the value of delivered items.
      // This is idempotent per-fulfillment via the accounting idempotency key.
      if (
        payload.status &&
        prevStatus !== OrderFulfillmentStatus.DELIVERED &&
        f.status === OrderFulfillmentStatus.DELIVERED
      ) {
        const order = await orderRepository.findOne({ where: { id: orderId } });
        if (!order) throw new NotFoundException('Order not found');

        const items = await orderItemRepository.find({ where: { orderId } });
        const itemsById = new Map(items.map((i) => [i.id, i] as const));

        const deliveredAmount = (f.fulfillmentItems ?? []).reduce((acc, fi) => {
          const item = itemsById.get(fi.orderItemId);
          if (!item) return acc;
          const qty = Number(item.quantity || 0);
          const total = Number(item.total || 0);
          if (!Number.isFinite(qty) || qty <= 0) return acc;
          if (!Number.isFinite(total)) return acc;
          const unit = total / qty;
          return acc + unit * Number(fi.quantity || 0);
        }, 0);

        // Only post if there is a meaningful amount to recognize.
        if (Number(deliveredAmount.toFixed(4)) > 0) {
          await this.accountingService.postRevenueRecognitionForFulfillment(
            manager,
            {
              fulfillmentId: f.id,
              orderId,
              currency: order.currencyCode,
              amount: Number(deliveredAmount.toFixed(4)),
              postedAt: f.deliveredAt ?? new Date(),
            },
          );
        }
      }

      // Event: status update (idempotent)
      if (payload.status) {
        await this.orderEvents.log(manager, {
          idempotencyKey: `fulfillment:${f.id}:${this.statusKey(f.status)}`,
          orderId,
          targetType: OrderEventTargetType.FULFILLMENT,
          targetId: f.id,
          action: `fulfillment.status.${this.statusKey(f.status)}`,
          actor,
          fulfillmentId: f.id,
          context: {
            orderId,
            fulfillmentId: f.id,
            status: f.status,
          },
        });

        await this.orderEvents.log(manager, {
          idempotencyKey: `order:${orderId}:fulfillment:${f.id}:${this.statusKey(f.status)}`,
          orderId,
          targetType: OrderEventTargetType.ORDER,
          targetId: orderId,
          action: `order.fulfillment.status.${this.statusKey(f.status)}`,
          actor,
          fulfillmentId: f.id,
          context: {
            orderId,
            fulfillmentId: f.id,
            status: f.status,
          },
        });

        for (const pkg of f.packages ?? []) {
          await this.orderEvents.log(manager, {
            idempotencyKey: `package:${pkg.id}:fulfillment:${f.id}:${this.statusKey(f.status)}`,
            orderId,
            targetType: OrderEventTargetType.PACKAGE,
            targetId: pkg.id,
            action: `package.fulfillment.status.${this.statusKey(f.status)}`,
            actor,
            fulfillmentId: f.id,
            packageId: pkg.id,
            context: {
              orderId,
              fulfillmentId: f.id,
              packageId: pkg.id,
              status: f.status,
            },
          });
        }
      }

      await this.recomputeOrderFulfillmentStatus(orderId, manager);
      return this.buildPublicFulfillmentShape(f);
    });
  }
}
