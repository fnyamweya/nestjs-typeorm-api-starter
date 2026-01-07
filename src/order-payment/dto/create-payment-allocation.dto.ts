import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  IsUUID,
  ValidateIf,
} from 'class-validator';
import { PaymentAllocationAppliesTo } from '../order-payment.types';

export class CreatePaymentAllocationDto {
  @ApiProperty({
    enum: PaymentAllocationAppliesTo,
    example: PaymentAllocationAppliesTo.ORDER,
  })
  @IsEnum(PaymentAllocationAppliesTo)
  appliesTo: PaymentAllocationAppliesTo;

  @ApiPropertyOptional({
    example: 'item_uuid',
    description: 'Required when appliesTo=ORDER_ITEM',
  })
  @ValidateIf((o) => o.appliesTo === PaymentAllocationAppliesTo.ORDER_ITEM)
  @IsUUID()
  orderItemId?: string;

  @ApiProperty({ example: 150000 })
  @IsNumber()
  amount: number;

  @ApiProperty({ example: 'KES' })
  @IsString()
  @IsNotEmpty()
  currency: string;

  @ApiPropertyOptional({ example: { note: 'optional allocation metadata' } })
  @IsOptional()
  metaJson?: Record<string, unknown>;
}
