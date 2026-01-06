import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { OrderItemChargeDto } from './order-item-charge.dto';

export class OrderItemDto {
  @ApiProperty({ example: '2f6f4c1f-7a01-4f2f-8d72-6d07d2b53d13' })
  id: string;

  @ApiProperty({ example: 'a0b1c2d3-e4f5-6789-0123-456789abcdef' })
  orderId: string;

  @ApiPropertyOptional({ example: 'c0ffee00-0000-0000-0000-000000000000' })
  productId?: string;

  @ApiPropertyOptional({ example: '3a3d0e5e-5b69-4c1f-8df3-7a6d7c2c0b11' })
  productSkuId?: string;

  @ApiPropertyOptional({ example: 'SKU-1' })
  sku?: string;

  @ApiPropertyOptional({ example: 'my-product-handle' })
  productHandle?: string;

  @ApiProperty({ example: 'SKU 1' })
  productName: string;

  @ApiPropertyOptional({ example: 'SKU 1' })
  skuTitle?: string;

  @ApiProperty({ type: Object, example: {} })
  skuOptionsJson: Record<string, unknown>;

  @ApiProperty({ type: Object, example: {} })
  attributesJson: Record<string, unknown>;

  @ApiProperty({ example: 2 })
  quantity: number;

  @ApiProperty({ example: '11111111-2222-3333-4444-555555555555' })
  priceListId: string;

  @ApiProperty({ example: '100.0000' })
  unitPrice: string;

  @ApiPropertyOptional({ example: '120.0000' })
  compareAtPrice?: string;

  @ApiProperty({ example: '200.0000' })
  baseSubtotal: string;

  @ApiProperty({ example: '20.0000' })
  discountTotal: string;

  @ApiProperty({ example: '0.0000' })
  feeTotal: string;

  @ApiProperty({ example: '28.8000' })
  taxTotal: string;

  @ApiProperty({ example: '208.8000' })
  total: string;

  @ApiProperty({ example: true })
  requiresShipping: boolean;

  @ApiProperty({ example: 'unfulfilled' })
  fulfillmentStatus: string;

  @ApiPropertyOptional({ example: 'default' })
  fulfillmentGroup?: string;

  @ApiProperty({ type: Object, example: {} })
  pricingSnapshotJson: Record<string, unknown>;

  @ApiProperty({ type: Object, example: {} })
  metaJson: Record<string, unknown>;

  @ApiProperty({ example: '2026-01-06T12:00:00.000Z' })
  createdAt: string;

  @ApiProperty({ example: '2026-01-06T12:00:00.000Z' })
  updatedAt: string;

  @ApiPropertyOptional({ type: () => [OrderItemChargeDto] })
  itemCharges?: OrderItemChargeDto[];
}
