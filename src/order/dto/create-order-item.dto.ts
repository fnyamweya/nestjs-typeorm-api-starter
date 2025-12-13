import { ApiProperty } from '@nestjs/swagger';
import { IsInt, IsNotEmpty, IsOptional, IsString, IsUUID } from 'class-validator';

export class CreateOrderItemDto {
  @ApiProperty({ description: 'Product variant id', example: '544e2b0b-...' })
  @IsUUID()
  productVariantId: string;

  @ApiProperty({ description: 'Quantity of this variant', example: 1 })
  @IsInt()
  quantity: number;

  @ApiProperty({ description: 'Optional SKU override', example: 'PROD-XXX' })
  @IsOptional()
  @IsString()
  sku?: string;
}
