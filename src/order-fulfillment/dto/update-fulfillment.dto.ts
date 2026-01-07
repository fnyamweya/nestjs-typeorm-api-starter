import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsDateString, IsEnum, IsObject, IsOptional, IsString, IsUUID, MaxLength, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { OrderFulfillmentStatus } from '../order-fulfillment.types';

class UpdateTrackingDto {
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

class UpdateTimestampsDto {
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

export class UpdateOrderFulfillmentDto {
  @ApiPropertyOptional({ enum: OrderFulfillmentStatus, example: OrderFulfillmentStatus.DELIVERED })
  @IsOptional()
  @IsEnum(OrderFulfillmentStatus)
  status?: OrderFulfillmentStatus;

  @ApiPropertyOptional({ example: 'ship_method_uuid' })
  @IsOptional()
  @IsUUID()
  shippingMethodId?: string;

  @ApiPropertyOptional({ type: () => UpdateTrackingDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => UpdateTrackingDto)
  tracking?: UpdateTrackingDto;

  @ApiPropertyOptional({ type: () => UpdateTimestampsDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => UpdateTimestampsDto)
  timestamps?: UpdateTimestampsDto;

  @ApiPropertyOptional({ example: { note: 'updated' } })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;
}
