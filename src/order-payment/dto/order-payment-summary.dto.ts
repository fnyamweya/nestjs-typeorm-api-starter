import { ApiProperty } from '@nestjs/swagger';
import { DerivedOrderPaymentStatus } from '../order-payment.types';

export class OrderPaymentSummaryDto {
  @ApiProperty({ example: 'ord_uuid' })
  orderId: string;

  @ApiProperty({ example: 'KES' })
  currency: string;

  @ApiProperty({ example: '150000.0000' })
  grandTotal: string;

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
