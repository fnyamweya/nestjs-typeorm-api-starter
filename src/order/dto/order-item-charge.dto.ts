import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class OrderItemChargeDto {
  @ApiProperty({ example: 'd7f7ed2b-4f3c-47a0-a2d7-10d6f6f3a2f0' })
  id: string;

  @ApiProperty({ example: '7b44dd5f-4cf6-44c8-baf2-5f2d3aa0c8b0' })
  orderItemId: string;

  @ApiProperty({
    example: 'discount',
    description: 'e.g. discount | tax | fee | shipping',
  })
  chargeKind: string;

  @ApiPropertyOptional({ example: 'PROMO10' })
  code?: string;

  @ApiProperty({ example: 'Promotion Discount' })
  displayName: string;

  @ApiProperty({ example: 'fixed', description: 'e.g. fixed | percentage' })
  calculationType: string;

  @ApiPropertyOptional({ example: '0.160000' })
  rate?: string;

  @ApiPropertyOptional({ example: '200.0000' })
  baseAmount?: string;

  @ApiPropertyOptional({ example: 2 })
  quantityBasis?: number;

  @ApiProperty({
    example: '-20.0000',
    description: 'Signed amount (discounts are negative)',
  })
  amount: string;

  @ApiProperty({ example: false })
  isIncludedInPrice: boolean;

  @ApiPropertyOptional({ example: 'promotion' })
  sourceType?: string;

  @ApiPropertyOptional({ example: 'a1b2c3' })
  sourceReference?: string;

  @ApiProperty({ type: Object, example: {} })
  metaJson: Record<string, unknown>;

  @ApiProperty({ example: '2026-01-06T12:00:00.000Z' })
  createdAt: string;
}
