import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  ValidateNested,
  IsOptional,
  IsUUID,
  IsString,
  IsNotEmpty,
} from 'class-validator';
import { Type } from 'class-transformer';
import { CreateOrderItemDto } from './create-order-item.dto';
import { UpsertAddressDto } from '../../address/dto/upsert-address.dto';

export class CreateOrderDto {
  @ApiProperty({
    description: 'Customer user id (UUID)',
    example: '0f3c7d0b-8bb6-4b48-9d53-71f2d9f0a1a9',
  })
  @IsUUID()
  customerId: string;

  @ApiProperty({
    description: 'Order line items',
    type: CreateOrderItemDto,
    isArray: true,
    example: [
      { productSkuId: '3a3d0e5e-5b69-4c1f-8df3-7a6d7c2c0b11', quantity: 2 },
    ],
  })
  @ValidateNested({ each: true })
  @Type(() => CreateOrderItemDto)
  @IsArray()
  orderItems: CreateOrderItemDto[];

  @ApiPropertyOptional({ description: 'Price list id to use for order' })
  @IsOptional()
  @IsUUID()
  priceListId?: string;

  @ApiPropertyOptional({
    description:
      "Shipping address created at checkout. This will be saved as the customer's shipping address and snapshotted onto the order so the order remains immutable.",
    type: UpsertAddressDto,
  })
  @IsOptional()
  @ValidateNested()
  @Type(() => UpsertAddressDto)
  shippingAddress?: UpsertAddressDto;

  // Shipping destination fields (optional for digital-only orders)
  @ApiPropertyOptional({
    description:
      'Shipping destination location id (UUID). This is used for shipping zone matching (locationId-only).',
    example: '9b2d2c8b-1a24-4f64-a1e6-0e8c1c3c9d10',
  })
  @IsOptional()
  @IsUUID()
  shippingLocationId?: string;

  @ApiPropertyOptional({
    description:
      'Chosen shipping method code for this order (e.g. "standard", "express"). Obtain candidates via POST /api/v1/shipping/quotes for the destination zone.',
    example: 'standard',
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  shippingMethodCode?: string;
}
