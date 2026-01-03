export const ORDER_PAYMENT_SUCCEEDED_EVENT = 'order.payment_succeeded';

export interface OrderPaymentSucceededEventPayload {
  orderId: string;
  msisdn?: string;
  amount?: string;
  transactionId?: string;
}
