import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { OrderDto } from './order.dto';

class ResponseMetaDto {
  @ApiPropertyOptional({ example: 100 })
  total?: number;

  @ApiPropertyOptional({ example: 1 })
  page?: number;

  @ApiPropertyOptional({ example: 10 })
  limit?: number;

  @ApiPropertyOptional({ example: 10 })
  totalPages?: number;
}

export class OrderResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: 200 })
  statusCode: number;

  @ApiProperty({ example: 'Order retrieved successfully' })
  message: string;

  @ApiProperty({ type: () => OrderDto })
  data: OrderDto;

  @ApiPropertyOptional({ type: () => ResponseMetaDto })
  meta?: ResponseMetaDto;

  @ApiProperty({ example: '2026-01-06T12:00:00.000Z' })
  timestamp: string;
}

export class OrdersListResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: 200 })
  statusCode: number;

  @ApiProperty({ example: 'Orders retrieved successfully' })
  message: string;

  @ApiProperty({
    type: () => [OrderDto],
    example: [
      {
        id: 'a0b1c2d3-e4f5-6789-0123-456789abcdef',
        orderNumber: 'ORD-1736170000000-123456',
        customerEmail: 'test@example.com',
        priceListId: '11111111-2222-3333-4444-555555555555',
        currencyCode: 'KES',
        status: 'pending',
        financialStatus: 'unpaid',
        fulfillmentStatus: 'unfulfilled',
        itemsSubtotal: '200.0000',
        discountTotal: '0.0000',
        feeTotal: '0.0000',
        taxTotal: '0.0000',
        shippingSubtotal: '0.0000',
        shippingDiscount: '0.0000',
        shippingTax: '0.0000',
        shippingTotal: '0.0000',
        grandTotal: '200.0000',
        itemCount: 1,
        metaJson: {},
        createdAt: '2026-01-06T12:00:00.000Z',
        updatedAt: '2026-01-06T12:00:00.000Z',
        paymentSummary: {
          capturedTotal: '0.0000',
          adjustedTotal: '0.0000',
          reversedTotal: '0.0000',
          refundedTotal: '0.0000',
          netPaidTotal: '0.0000',
          status: 'PENDING',
        },
      },
    ],
  })
  data: OrderDto[];

  @ApiPropertyOptional({
    type: () => ResponseMetaDto,
    example: { total: 1, page: 1, limit: 10, totalPages: 1 },
  })
  meta?: ResponseMetaDto;

  @ApiProperty({ example: '2026-01-06T12:00:00.000Z' })
  timestamp: string;
}
