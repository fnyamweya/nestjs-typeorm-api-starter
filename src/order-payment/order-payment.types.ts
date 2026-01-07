export enum OrderPaymentType {
  CAPTURE = 'CAPTURE',
  REVERSAL = 'REVERSAL',
  REFUND = 'REFUND',
  ADJUSTMENT = 'ADJUSTMENT',
}

export enum OrderPaymentStatus {
  PENDING = 'PENDING',
  SUCCEEDED = 'SUCCEEDED',
  FAILED = 'FAILED',
  CANCELLED = 'CANCELLED',
}

export enum PaymentAllocationAppliesTo {
  ORDER = 'ORDER',
  ORDER_ITEM = 'ORDER_ITEM',
}

export enum DerivedOrderPaymentStatus {
  PENDING = 'PENDING',
  PARTIALLY_PAID = 'PARTIALLY_PAID',
  PAID = 'PAID',
  OVERPAID = 'OVERPAID',
  PARTIALLY_REFUNDED = 'PARTIALLY_REFUNDED',
  REFUNDED = 'REFUNDED',
}
