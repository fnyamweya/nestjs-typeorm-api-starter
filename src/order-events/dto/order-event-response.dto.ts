import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

class ResponseMetaDto {
  @ApiPropertyOptional({ example: 100 })
  total?: number;

  @ApiPropertyOptional({ example: 1 })
  page?: number;

  @ApiPropertyOptional({ example: 20 })
  limit?: number;

  @ApiPropertyOptional({ example: 5 })
  totalPages?: number;
}

export class OrderEventsListResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: 200 })
  statusCode: number;

  @ApiProperty({ example: 'Order events retrieved successfully' })
  message: string;

  @ApiProperty({
    type: Array,
    example: [
      {
        id: 'evt_uuid',
        orderId: 'ord_uuid',
        targetType: 'fulfillment',
        targetId: 'ful_uuid',
        action: 'fulfillment.status.shipped',
        idempotencyKey: 'fulfillment:ful_uuid:shipped',
        actor: { type: 'user', id: 'user_uuid', email: 'admin@example.com' },
        previous: { id: 'prev_evt_uuid', action: 'fulfillment.created', createdAt: '2026-01-07T10:00:00Z' },
        next: { action: 'fulfillment.status.delivered', actions: ['fulfillment.status.delivered', 'fulfillment.status.cancelled'] },
        context: { status: 'SHIPPED', fulfillmentId: 'ful_uuid' },
        createdAt: '2026-01-07T10:05:00Z',
      },
    ],
  })
  data: any[];

  @ApiPropertyOptional({ type: () => ResponseMetaDto })
  meta?: ResponseMetaDto;

  @ApiProperty({ example: '2026-01-07T10:05:00Z' })
  timestamp: string;
}
