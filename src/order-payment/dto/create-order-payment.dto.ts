import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsDateString,
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { OrderPaymentStatus, OrderPaymentType } from '../order-payment.types';
import { CreatePaymentAllocationDto } from './create-payment-allocation.dto';

export class CreateOrderPaymentDto {
  @ApiProperty({ enum: OrderPaymentType, example: OrderPaymentType.CAPTURE })
  @IsEnum(OrderPaymentType)
  type: OrderPaymentType;

  @ApiProperty({
    enum: OrderPaymentStatus,
    example: OrderPaymentStatus.SUCCEEDED,
  })
  @IsEnum(OrderPaymentStatus)
  status: OrderPaymentStatus;

  @ApiProperty({ example: 'MNO' })
  @IsString()
  @IsNotEmpty()
  provider: string;

  @ApiProperty({ example: 'MOBILE_MONEY' })
  @IsString()
  @IsNotEmpty()
  method: string;

  @ApiProperty({ example: 150000 })
  @IsNumber()
  amount: number;

  @ApiProperty({ example: 'KES' })
  @IsString()
  @IsNotEmpty()
  currency: string;

  @ApiPropertyOptional({ example: 'mno_txn_123' })
  @IsOptional()
  @IsString()
  @MaxLength(255)
  externalRef?: string;

  @ApiPropertyOptional({ example: '2026-01-03T10:21:00Z' })
  @IsOptional()
  @IsDateString()
  initiatedAt?: string;

  @ApiPropertyOptional({ example: '2026-01-03T10:21:20Z' })
  @IsOptional()
  @IsDateString()
  confirmedAt?: string;

  @ApiPropertyOptional({ example: { msisdn: '+2547xxxxxxx' } })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;

  @ApiPropertyOptional({ type: () => [CreatePaymentAllocationDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreatePaymentAllocationDto)
  allocations?: CreatePaymentAllocationDto[];
}
