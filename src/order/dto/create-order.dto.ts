import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsArray, IsEmail, IsNotEmpty, ValidateNested, IsOptional, IsUUID } from 'class-validator';
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
}
