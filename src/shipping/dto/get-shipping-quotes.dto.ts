import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Min,
  ValidateNested,
} from 'class-validator';

export class ShippingQuoteItemDto {
  @ApiProperty({
    description: 'Product SKU id (UUID)',
    example: '3a3d0e5e-5b69-4c1f-8df3-7a6d7c2c0b11',
  })
  @IsUUID()
  productSkuId: string;

  @ApiProperty({ description: 'Quantity', example: 2 })
  @IsInt()
  @Min(1)
  quantity: number;
}

export class GetShippingQuotesDto {
  @ApiProperty({
    description: 'Shipping destination location id (UUID)',
    example: '9b2d2c8b-1a24-4f64-a1e6-0e8c1c3c9d10',
  })
  @IsUUID()
  shippingLocationId: string;

  @ApiProperty({
    description: 'Order line items',
    type: ShippingQuoteItemDto,
    isArray: true,
    example: [
      { productSkuId: '3a3d0e5e-5b69-4c1f-8df3-7a6d7c2c0b11', quantity: 2 },
    ],
  })
  @ValidateNested({ each: true })
  @Type(() => ShippingQuoteItemDto)
  @IsArray()
  orderItems: ShippingQuoteItemDto[];

  @ApiPropertyOptional({
    description: 'Price list id to use for pricing (UUID)',
  })
  @IsOptional()
  @IsUUID()
  priceListId?: string;

  @ApiPropertyOptional({
    description: 'Currency code (e.g., KES)',
    example: 'KES',
  })
  @IsOptional()
  @IsString()
  currencyCode?: string;

  @ApiPropertyOptional({
    description:
      'Optional sales channel code. If provided, channel-targeted shipping rates can be applied.',
    example: 'default',
  })
  @IsOptional()
  @IsString()
  salesChannelCode?: string;
}
