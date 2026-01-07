import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { OrderItemDto } from './order-item.dto';
import { OrderLevelChargeDto } from './order-level-charge.dto';
import { DerivedOrderPaymentStatus } from '../../order-payment/order-payment.types';

class OrderPaymentSummaryDto {
  @ApiProperty({ example: '100000.0000' })
  capturedTotal: string;

  @ApiProperty({ example: '0.0000' })
  adjustedTotal: string;

  @ApiProperty({ example: '0.0000' })
  reversedTotal: string;

  @ApiProperty({ example: '0.0000' })
  refundedTotal: string;

  @ApiProperty({ example: '100000.0000' })
  netPaidTotal: string;

  @ApiProperty({
    enum: DerivedOrderPaymentStatus,
    example: DerivedOrderPaymentStatus.PARTIALLY_PAID,
  })
  status: DerivedOrderPaymentStatus;
}

export class OrderDto {
  @ApiProperty({ example: 'a0b1c2d3-e4f5-6789-0123-456789abcdef' })
  id: string;

  @ApiProperty({ example: 'ORD-1736170000000-123456' })
  orderNumber: string;

  @ApiPropertyOptional({ example: 'external-123' })
  externalId?: string;

  @ApiPropertyOptional({ example: '0f3c7d0b-8bb6-4b48-9d53-71f2d9f0a1a9' })
  customerId?: string;

  @ApiProperty({ example: 'test@example.com' })
  customerEmail: string;

  @ApiPropertyOptional({ example: 'Test Customer' })
  customerName?: string;

  @ApiProperty({ example: '11111111-2222-3333-4444-555555555555' })
  priceListId: string;

  @ApiProperty({ example: 'KES' })
  currencyCode: string;

  @ApiPropertyOptional({ example: 'en-KE' })
  locale?: string;

  @ApiPropertyOptional({ example: 'web' })
  salesChannelCode?: string;

  @ApiPropertyOptional({ example: '127.0.0.1' })
  ipAddress?: string;

  @ApiPropertyOptional({ example: 'Mozilla/5.0 ...' })
  userAgent?: string;

  @ApiProperty({ example: 'pending' })
  status: string;

  @ApiProperty({ example: 'unpaid' })
  financialStatus: string;

  @ApiProperty({ example: 'unfulfilled' })
  fulfillmentStatus: string;

  @ApiPropertyOptional({ example: 'low_risk' })
  riskState?: string;

  @ApiProperty({ example: '200.0000' })
  itemsSubtotal: string;

  @ApiProperty({ example: '20.0000' })
  discountTotal: string;

  @ApiProperty({ example: '0.0000' })
  feeTotal: string;

  @ApiProperty({ example: '28.8000', description: 'Tax allocated to items' })
  taxTotal: string;

  @ApiProperty({ example: '50.0000' })
  shippingSubtotal: string;

  @ApiProperty({ example: '0.0000' })
  shippingDiscount: string;

  @ApiProperty({ example: '8.0000', description: 'Tax allocated to shipping' })
  shippingTax: string;

  @ApiProperty({ example: '58.0000' })
  shippingTotal: string;

  @ApiProperty({ example: '266.8000' })
  grandTotal: string;

  @ApiProperty({ example: 2 })
  itemCount: number;

  @ApiPropertyOptional({ example: 'Leave at the door' })
  notesCustomer?: string;

  @ApiPropertyOptional({ example: 'Internal note' })
  notesInternal?: string;

  @ApiPropertyOptional({ type: () => [String], example: ['priority'] })
  tags?: string[];

  @ApiProperty({ type: Object, example: {} })
  metaJson: Record<string, unknown>;

  @ApiPropertyOptional({ example: '2026-01-06T12:00:00.000Z' })
  placedAt?: string;

  @ApiPropertyOptional({ example: '2026-01-06T12:00:00.000Z' })
  confirmedAt?: string;

  @ApiPropertyOptional({ example: '2026-01-06T12:00:00.000Z' })
  cancelledAt?: string;

  @ApiPropertyOptional({ example: '2026-01-06T12:00:00.000Z' })
  completedAt?: string;

  @ApiProperty({ example: '2026-01-06T12:00:00.000Z' })
  createdAt: string;

  @ApiProperty({ example: '2026-01-06T12:00:00.000Z' })
  updatedAt: string;

  @ApiPropertyOptional({ type: () => [OrderItemDto] })
  items?: OrderItemDto[];

  @ApiPropertyOptional({ type: () => [OrderLevelChargeDto] })
  orderLevelCharges?: OrderLevelChargeDto[];

  @ApiPropertyOptional({
    type: () => OrderPaymentSummaryDto,
    example: {
      capturedTotal: '0.0000',
      adjustedTotal: '0.0000',
      reversedTotal: '0.0000',
      refundedTotal: '0.0000',
      netPaidTotal: '0.0000',
      status: DerivedOrderPaymentStatus.PENDING,
    },
    description: 'Derived from successful payment allocations; no DB field.',
  })
  paymentSummary?: OrderPaymentSummaryDto;
}
