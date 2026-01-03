import { Injectable } from '@nestjs/common';
import { SmsServiceUtils } from '../../common/utils/sms-service.utils';

@Injectable()
export class OrderSmsService {
  constructor(private readonly sms: SmsServiceUtils) {}

  async sendOrderPaidSms(input: {
    to: string;
    orderNumber: string;
    amount?: string;
  }): Promise<void> {
    const amountPart = input.amount ? ` Amount: ${input.amount}.` : '';

    await this.sms.sendSms({
      to: input.to,
      message: `Payment received for order ${input.orderNumber}.${amountPart} Thank you for shopping with us.`,
    });
  }
}
