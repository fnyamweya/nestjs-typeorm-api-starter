import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsDateString,
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsNumber,
  IsObject,
  IsOptional,
  IsPositive,
  IsString,
  IsUUID,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { OrderFulfillmentStatus } from '../order-fulfillment.types';

class TrackingDto {
  @ApiPropertyOptional({ example: 'TRK123' })
  @IsOptional()
  @IsString()
  @MaxLength(128)
  trackingNumber?: string;

  @ApiPropertyOptional({ example: 'https://carrier.example/track/TRK123' })
  @IsOptional()
  @IsString()
  @MaxLength(2048)
  trackingUrl?: string;
}

class OriginDto {
  @ApiPropertyOptional({ example: 'loc_uuid' })
  @IsOptional()
  @IsUUID()
  locationId?: string;

  @ApiPropertyOptional({ example: 'Nairobi' })
  @IsOptional()
  @IsString()
  @MaxLength(255)
  name?: string;
}

class WeightDto {
  @ApiProperty({ example: 2.3 })
  @IsNumber()
  @IsPositive()
  value: number;

  @ApiProperty({ example: 'kg' })
  @IsString()
  @IsNotEmpty()
  unit: string;
}

class DimensionsDto {
  @ApiProperty({ example: 30 })
  @IsNumber()
  @IsPositive()
  length: number;

  @ApiProperty({ example: 20 })
  @IsNumber()
  @IsPositive()
  width: number;

  @ApiProperty({ example: 10 })
  @IsNumber()
  @IsPositive()
  height: number;

  @ApiProperty({ example: 'cm' })
  @IsString()
  @IsNotEmpty()
  unit: string;
}

export class CreatePackageItemDto {
  @ApiProperty({ example: 'item_uuid' })
  @IsUUID()
  orderItemId: string;

  @ApiProperty({ example: 1 })
  @IsInt()
  @IsPositive()
  quantity: number;
}

export class CreateFulfillmentPackageDto {
  @ApiPropertyOptional({ example: { value: 2.3, unit: 'kg' } })
  @IsOptional()
  @ValidateNested()
  @Type(() => WeightDto)
  weight?: WeightDto;

  @ApiPropertyOptional({ example: { length: 30, width: 20, height: 10, unit: 'cm' } })
  @IsOptional()
  @ValidateNested()
  @Type(() => DimensionsDto)
  dimensions?: DimensionsDto;

  @ApiPropertyOptional({ example: 'TRK123-1' })
  @IsOptional()
  @IsString()
  @MaxLength(128)
  trackingNumber?: string;

  @ApiProperty({ type: () => [CreatePackageItemDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreatePackageItemDto)
  items: CreatePackageItemDto[];

  @ApiPropertyOptional({ example: {} })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;
}

export class CreateFulfillmentItemDto {
  @ApiProperty({ example: 'item_uuid' })
  @IsUUID()
  orderItemId: string;

  @ApiProperty({ example: 2 })
  @IsInt()
  @IsPositive()
  quantity: number;
}

class CostDto {
  @ApiProperty({ example: 'KES' })
  @IsString()
  @IsNotEmpty()
  currency: string;

  @ApiProperty({ example: 5000 })
  @IsNumber()
  shippingAmount: number;

  @ApiPropertyOptional({ example: 0 })
  @IsOptional()
  @IsNumber()
  insuranceAmount?: number;
}

class TimestampsDto {
  @ApiPropertyOptional({ example: '2026-01-03T10:40:00Z' })
  @IsOptional()
  @IsDateString()
  packedAt?: string;

  @ApiPropertyOptional({ example: '2026-01-03T11:00:00Z' })
  @IsOptional()
  @IsDateString()
  shippedAt?: string;

  @ApiPropertyOptional({ example: null, nullable: true })
  @IsOptional()
  deliveredAt?: string | null;
}

export class CreateOrderFulfillmentDto {
  @ApiProperty({ enum: OrderFulfillmentStatus, example: OrderFulfillmentStatus.SHIPPED })
  @IsEnum(OrderFulfillmentStatus)
  status: OrderFulfillmentStatus;

  @ApiPropertyOptional({
    example: 'ship_method_uuid',
    description: 'Shipping method id from shipping methods endpoint. Will be snapshotted.',
  })
  @IsOptional()
  @IsUUID()
  shippingMethodId?: string;

  @ApiPropertyOptional({ type: () => TrackingDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => TrackingDto)
  tracking?: TrackingDto;

  @ApiPropertyOptional({ type: () => OriginDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => OriginDto)
  origin?: OriginDto;

  @ApiPropertyOptional({
    example: { firstName: 'Jane', lastName: 'Doe', phone: '254700000000', countryCode: 'KE', locationId: 'loc_uuid' },
    description: 'Optional override; defaults to order shipping address snapshot.',
  })
  @IsOptional()
  @IsObject()
  destination?: Record<string, unknown>;

  @ApiProperty({ type: () => [CreateFulfillmentPackageDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateFulfillmentPackageDto)
  packages: CreateFulfillmentPackageDto[];

  @ApiPropertyOptional({
    type: () => [CreateFulfillmentItemDto],
    description: 'If provided, must equal sum(packages.items) by orderItemId.',
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateFulfillmentItemDto)
  fulfillmentItems?: CreateFulfillmentItemDto[];

  @ApiPropertyOptional({ type: () => CostDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => CostDto)
  cost?: CostDto;

  @ApiPropertyOptional({ type: () => TimestampsDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => TimestampsDto)
  timestamps?: TimestampsDto;

  @ApiPropertyOptional({ example: { carrierJobId: 'sendy_job_999' } })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;
}
