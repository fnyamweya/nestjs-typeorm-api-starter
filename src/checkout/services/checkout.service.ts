import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CheckoutSession } from '../entities/checkout-session.entity';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { CreateCheckoutSessionDto } from '../dto/create-checkout-session.dto';
import { SetCheckoutDeliveryDto } from '../dto/set-checkout-delivery.dto';
import { SetCheckoutShippingMethodDto } from '../dto/set-checkout-shipping-method.dto';
import { ShippingQuotesService } from 'src/shipping/services/shipping-quotes.service';
import { CustomerShippingAddressService } from 'src/customer-shipping-address/services/customer-shipping-address.service';
import { QueueService } from 'src/queue/queue.service';
import { OrderService } from 'src/order/services/order.service';

const CHECKOUT_QUEUE = 'checkout';
const EXPIRE_JOB = 'expire-session';

type CheckoutSessionState = {
  orderItems: Array<{ productSkuId: string; quantity: number }>;
  priceListId?: string;
  currencyCode?: string;
  shippingLocationId?: string;
  shippingMethodCode?: string;
  deliverySetAt?: string;
  shippingMethodSetAt?: string;
};

@Injectable()
export class CheckoutService {
  private readonly ttlSeconds = 60 * 30; // 30 minutes

  constructor(
    @InjectRepository(CheckoutSession)
    private readonly checkoutSessionRepo: Repository<CheckoutSession>,
    private readonly cache: AppCacheService,
    private readonly queueService: QueueService,
    private readonly shippingQuotesService: ShippingQuotesService,
    private readonly customerShippingAddressService: CustomerShippingAddressService,
    private readonly orderService: OrderService,
  ) {}

  private key(sessionId: string) {
    return `checkout:session:${sessionId}`;
  }

  private async loadRowOrThrow(userId: string, sessionId: string) {
    const row = await this.checkoutSessionRepo.findOne({
      where: { id: sessionId, userId },
    });
    if (!row) throw new NotFoundException('Checkout session not found');
    if (row.status !== 'active') {
      throw new BadRequestException(`Checkout session is ${row.status}`);
    }
    if (row.expiresAt.getTime() <= Date.now()) {
      throw new BadRequestException('Checkout session expired');
    }
    return row;
  }

  private async loadStateOrThrow(
    sessionId: string,
  ): Promise<CheckoutSessionState> {
    const state = await this.cache.get<CheckoutSessionState>(
      this.key(sessionId),
    );
    if (!state) throw new NotFoundException('Checkout session state not found');
    if (!Array.isArray(state.orderItems) || !state.orderItems.length) {
      throw new BadRequestException('Checkout session has no items');
    }
    return state;
  }

  async createSession(userId: string, payload: CreateCheckoutSessionDto) {
    const orderItems = (payload.orderItems ?? [])
      .map((i) => ({
        productSkuId: String(i.productSkuId),
        quantity: Number(i.quantity),
      }))
      .filter((i) => i.productSkuId && i.quantity > 0);

    if (!orderItems.length)
      throw new BadRequestException('orderItems is required');

    const expiresAt = new Date(Date.now() + this.ttlSeconds * 1000);

    const created = await this.checkoutSessionRepo.save(
      this.checkoutSessionRepo.create({
        userId,
        status: 'active',
        expiresAt,
        metaJson: {},
      }),
    );

    const state: CheckoutSessionState = {
      orderItems,
      priceListId: payload.priceListId,
      currencyCode: payload.currencyCode,
    };

    await this.cache.set(this.key(created.id), state, this.ttlSeconds);

    if (process.env.NODE_ENV !== 'test') {
      await this.queueService.addJob(
        CHECKOUT_QUEUE,
        EXPIRE_JOB,
        { sessionId: created.id },
        { delay: this.ttlSeconds * 1000, jobId: `expire:${created.id}` },
      );
    }

    return {
      id: created.id,
      status: created.status,
      expiresAt: created.expiresAt,
    };
  }

  async setDelivery(
    userId: string,
    sessionId: string,
    payload: SetCheckoutDeliveryDto,
  ) {
    await this.loadRowOrThrow(userId, sessionId);
    const state = await this.loadStateOrThrow(sessionId);

    if (!payload.shippingAddress?.locationId) {
      throw new BadRequestException('shippingAddress.locationId is required');
    }

    await this.customerShippingAddressService.upsertForUser(
      userId,
      payload.shippingAddress,
    );

    const next: CheckoutSessionState = {
      ...state,
      shippingLocationId: payload.shippingAddress.locationId,
      deliverySetAt: new Date().toISOString(),
    };

    await this.cache.set(this.key(sessionId), next, this.ttlSeconds);

    return {
      id: sessionId,
      shippingLocationId: next.shippingLocationId,
      deliverySetAt: next.deliverySetAt,
    };
  }

  async getShippingMethods(userId: string, sessionId: string) {
    await this.loadRowOrThrow(userId, sessionId);
    const state = await this.loadStateOrThrow(sessionId);

    const shippingLocationId = state.shippingLocationId;
    if (!shippingLocationId) {
      throw new BadRequestException(
        'Delivery is required before listing shipping methods',
      );
    }

    const quotes = await this.shippingQuotesService.getQuotes({
      shippingLocationId,
      orderItems: state.orderItems,
      priceListId: state.priceListId,
      currencyCode: state.currencyCode,
    });

    return { shippingLocationId, quotes };
  }

  async setShippingMethod(
    userId: string,
    sessionId: string,
    payload: SetCheckoutShippingMethodDto,
  ) {
    await this.loadRowOrThrow(userId, sessionId);
    const state = await this.loadStateOrThrow(sessionId);

    const shippingLocationId = state.shippingLocationId;
    if (!shippingLocationId) {
      throw new BadRequestException(
        'Delivery is required before choosing a shipping method',
      );
    }

    const quotes = await this.shippingQuotesService.getQuotes({
      shippingLocationId,
      orderItems: state.orderItems,
      priceListId: state.priceListId,
      currencyCode: state.currencyCode,
    });

    const code = String(payload.shippingMethodCode).trim();
    const exists = quotes.some((q: any) => q?.method?.code === code);
    if (!exists) {
      throw new BadRequestException(
        'Selected shipping method is not available for this destination',
      );
    }

    const next: CheckoutSessionState = {
      ...state,
      shippingMethodCode: code,
      shippingMethodSetAt: new Date().toISOString(),
    };

    await this.cache.set(this.key(sessionId), next, this.ttlSeconds);

    return {
      id: sessionId,
      shippingMethodCode: next.shippingMethodCode,
      shippingMethodSetAt: next.shippingMethodSetAt,
    };
  }

  async review(userId: string, sessionId: string) {
    const row = await this.loadRowOrThrow(userId, sessionId);
    const state = await this.loadStateOrThrow(sessionId);

    const shippingAddressRow = await this.customerShippingAddressService
      .getOptionalForUser(userId)
      .catch(() => null);

    const shippingAddress = shippingAddressRow?.address ?? null;

    const shippingLocationId =
      state.shippingLocationId ?? shippingAddress?.locationId ?? null;

    const quotes = shippingLocationId
      ? await this.shippingQuotesService.getQuotes({
          shippingLocationId,
          orderItems: state.orderItems,
          priceListId: state.priceListId,
          currencyCode: state.currencyCode,
        })
      : [];

    const selected = state.shippingMethodCode
      ? (quotes.find(
          (q: any) => q?.method?.code === state.shippingMethodCode,
        ) ?? null)
      : null;

    return {
      id: sessionId,
      status: row.status,
      orderItems: state.orderItems,
      shippingAddress,
      shippingLocationId,
      shippingMethodCode: state.shippingMethodCode ?? null,
      selectedShippingQuote: selected,
      quotes,
      expiresInSeconds: Math.max(
        0,
        Math.floor((row.expiresAt.getTime() - Date.now()) / 1000),
      ),
    };
  }

  async confirm(userId: string, sessionId: string) {
    const row = await this.loadRowOrThrow(userId, sessionId);
    const state = await this.loadStateOrThrow(sessionId);

    const shippingAddress = await this.customerShippingAddressService
      .getOptionalForUser(userId)
      .catch(() => null);

    const shippingLocationId =
      state.shippingLocationId ??
      shippingAddress?.address?.locationId ??
      undefined;

    if (shippingLocationId && !state.shippingMethodCode) {
      throw new BadRequestException('Shipping method is required');
    }

    const order = await this.orderService.create({
      customerId: userId,
      orderItems: state.orderItems,
      priceListId: state.priceListId,
      shippingLocationId,
      shippingMethodCode: state.shippingMethodCode,
    });

    row.status = 'completed';
    row.completedAt = new Date();
    await this.checkoutSessionRepo.save(row);

    await this.cache.del(this.key(sessionId));

    return { sessionId, order };
  }
}
