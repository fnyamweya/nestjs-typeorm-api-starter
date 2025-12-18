import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsArray, IsEmail, IsNotEmpty, ValidateNested, IsOptional, IsUUID, IsString } from 'class-validator';
import { Type } from 'class-transformer';
import { CreateOrderItemDto } from './create-order-item.dto';

export class CreateOrderDto {
  @ApiProperty({ description: 'Customer email' })
  @IsEmail()
  customerEmail: string;

  @ApiPropertyOptional({ description: 'Customer name' })
  @IsOptional()
  @IsNotEmpty()
  customerName?: string;

  @ApiProperty({ description: 'Order line items', type: CreateOrderItemDto, isArray: true })
  @ValidateNested({ each: true })
  @Type(() => CreateOrderItemDto)
  @IsArray()
  items: CreateOrderItemDto[];

  @ApiPropertyOptional({ description: 'Price list id to use for order' })
  @IsOptional()
  @IsUUID()
  priceListId?: string;

  // Shipping destination fields (optional for digital-only orders)
  @ApiPropertyOptional({ description: 'Shipping country ISO2 code (e.g., US, KE)' })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  shippingCountry?: string;

  @ApiPropertyOptional({ description: 'Shipping region/state' })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  shippingRegion?: string;

  @ApiPropertyOptional({ description: 'Shipping postal code' })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  shippingPostalCode?: string;

  @ApiPropertyOptional({ description: 'Shipping city' })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  shippingCity?: string;

  @ApiPropertyOptional({ description: 'Shipping address line 1' })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  shippingAddressLine1?: string;

  @ApiPropertyOptional({ description: 'Shipping address line 2' })
  @IsOptional()
  @IsString()
  shippingAddressLine2?: string;

  @ApiPropertyOptional({ description: 'Shipping phone number' })
  @IsOptional()
  @IsString()
  shippingPhone?: string;
}
