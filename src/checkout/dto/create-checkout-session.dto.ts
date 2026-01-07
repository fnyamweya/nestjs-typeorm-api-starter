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

export class CheckoutItemDto {
  @ApiProperty({ description: 'Product SKU id (UUID)' })
  @IsUUID()
  productSkuId: string;

  @ApiProperty({ description: 'Quantity', example: 1 })
  @IsInt()
  @Min(1)
  quantity: number;
}

export class CreateCheckoutSessionDto {
  @ApiProperty({ type: CheckoutItemDto, isArray: true })
  @ValidateNested({ each: true })
  @Type(() => CheckoutItemDto)
  @IsArray()
  orderItems: CheckoutItemDto[];

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
}
