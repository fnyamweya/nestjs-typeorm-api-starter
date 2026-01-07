import { ApiProperty } from '@nestjs/swagger';
import {
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUUID,
} from 'class-validator';

export class CreateOrderItemDto {
  @ApiProperty({ description: 'Product SKU id', example: '544e2b0b-...' })
  @IsUUID()
  productSkuId: string;

  @ApiProperty({ description: 'Quantity of this SKU', example: 1 })
  @IsInt()
  quantity: number;

  @ApiProperty({ description: 'Optional SKU override', example: 'PROD-XXX' })
  @IsOptional()
  @IsString()
  sku?: string;
}
