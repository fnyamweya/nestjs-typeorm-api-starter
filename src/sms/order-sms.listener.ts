import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { EventBusService } from '../queue/event-bus.service';
import {
  ORDER_PAYMENT_SUCCEEDED_EVENT,
  OrderPaymentSucceededEventPayload,
} from '../order/order.events';
import { Order } from '../order/entities/order.entity';
import { User } from '../user/entities/user.entity';
import { normalizeProfilePreferences } from '../user/profile-preferences';
import { OrderSmsService } from './services/order-sms.service';

@Injectable()
export class OrderSmsListener implements OnModuleInit {
  private readonly logger = new Logger(OrderSmsListener.name);

  constructor(
    private readonly eventBus: EventBusService,
    private readonly orderSms: OrderSmsService,
    @InjectRepository(Order)
    private readonly orderRepo: Repository<Order>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
  ) {}

  async onModuleInit() {
    await this.eventBus.subscribe<OrderPaymentSucceededEventPayload>(
      ORDER_PAYMENT_SUCCEEDED_EVENT,
      async (payload) => {
        await this.handleOrderPaid(payload);
      },
    );
  }

  private async handleOrderPaid(payload: OrderPaymentSucceededEventPayload) {
    const order = await this.orderRepo.findOne({
      where: { id: payload.orderId },
    });
    if (!order) {
      this.logger.warn(`Order not found for paid event: ${payload.orderId}`);
      return;
    }

    // If this order is linked to a registered user, respect their SMS preferences.
    if (order.customerId) {
      const user = await this.userRepo.findOne({
        where: { id: order.customerId },
      });
      if (!user?.phone) return;

      const prefs = normalizeProfilePreferences(user.profilePreferences);
      const allowSms = !!prefs.notifications.sms.enabled;
      const allowOrderUpdates = !!prefs.notifications.sms.orderUpdates;

      if (!allowSms || !allowOrderUpdates) return;

      await this.orderSms.sendOrderPaidSms({
        to: user.phone,
        orderNumber: order.orderNumber,
        amount: payload.amount ?? order.grandTotal,
      });

      return;
    }

    // Otherwise, fall back to the payer MSISDN (no user prefs available).
    if (!payload.msisdn) return;

    await this.orderSms.sendOrderPaidSms({
      to: payload.msisdn,
      orderNumber: order.orderNumber,
      amount: payload.amount ?? order.grandTotal,
    });
  }
}
