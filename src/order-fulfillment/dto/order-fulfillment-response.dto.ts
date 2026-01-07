import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

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

export class OrderFulfillmentResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: 200 })
  statusCode: number;

  @ApiProperty({ example: 'Fulfillment retrieved successfully' })
  message: string;

  @ApiProperty({
    type: Object,
    example: {
      id: 'ful_uuid',
      orderId: 'ord_uuid',
      status: 'SHIPPED',
      shippingMethod: { id: 'ship_method_uuid', code: 'express', displayName: 'Express', provider: 'sendy' },
      tracking: { trackingNumber: 'TRK123', trackingUrl: 'https://carrier.example/track/TRK123' },
      origin: { locationId: 'loc_uuid', name: 'Nairobi' },
      destination: { firstName: 'Jane', lastName: 'Doe', phone: '254700000000', countryCode: 'KE', locationId: 'loc_uuid' },
      packages: [
        {
          packageId: 'pkg_uuid',
          weight: { value: 2.3, unit: 'kg' },
          dimensions: { length: 30, width: 20, height: 10, unit: 'cm' },
          trackingNumber: 'TRK123-1',
          items: [
            { orderItemId: 'item_uuid', quantity: 1 },
          ],
        },
      ],
      fulfillmentItems: [
        { orderItemId: 'item_uuid', quantity: 1 },
      ],
      cost: { currency: 'KES', shippingAmount: 5000, insuranceAmount: 0 },
      timestamps: { packedAt: '2026-01-03T10:40:00Z', shippedAt: '2026-01-03T11:00:00Z', deliveredAt: null },
      metaJson: { carrierJobId: 'sendy_job_999' },
      createdAt: '2026-01-03T10:35:00Z',
      updatedAt: '2026-01-03T11:00:00Z',
    },
  })
  data: any;

  @ApiPropertyOptional({ type: () => ResponseMetaDto })
  meta?: ResponseMetaDto;

  @ApiProperty({ example: '2026-01-03T10:35:00Z' })
  timestamp: string;
}

export class OrderFulfillmentsListResponseDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: 200 })
  statusCode: number;

  @ApiProperty({ example: 'Fulfillments retrieved successfully' })
  message: string;

  @ApiProperty({
    type: Array,
    example: [
      {
        id: 'ful_uuid',
        orderId: 'ord_uuid',
        status: 'SHIPPED',
        tracking: { trackingNumber: 'TRK123' },
        createdAt: '2026-01-03T10:35:00Z',
        updatedAt: '2026-01-03T11:00:00Z',
      },
    ],
  })
  data: any[];

  @ApiPropertyOptional({ type: () => ResponseMetaDto })
  meta?: ResponseMetaDto;

  @ApiProperty({ example: '2026-01-03T10:35:00Z' })
  timestamp: string;
}
