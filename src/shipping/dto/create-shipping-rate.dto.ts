import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString, IsNumber } from 'class-validator';

export class CreateShippingRateDto {
  @ApiProperty({ description: 'Shipping method id' })
  @IsNotEmpty()
  methodId: string;

  @ApiProperty({ description: 'Calculation type', example: 'flat', enum: ['flat','per_weight','per_item','table_rate','formula'] })
  @IsString()
  @IsNotEmpty()
  calculationType: 'flat' | 'per_weight' | 'per_item' | 'table_rate' | 'formula';

  @ApiProperty({ description: 'Price', example: '50.00', required: false })
  @IsOptional()
  price?: string;

  @ApiPropertyOptional({ description: 'Min weight threshold' })
  @IsOptional()
  minWeight?: string;

  @ApiPropertyOptional({ description: 'Max weight threshold' })
  @IsOptional()
  maxWeight?: string;

  @ApiPropertyOptional({ description: 'Min subtotal' })
  @IsOptional()
  minSubtotal?: string;

  @ApiPropertyOptional({ description: 'Max subtotal' })
  @IsOptional()
  maxSubtotal?: string;

  @ApiPropertyOptional({ description: 'Price per unit (for per_weight or per_item)' })
  @IsOptional()
  pricePerUnit?: string;

  @ApiPropertyOptional({ description: 'Priority (lower number = higher priority)' })
  @IsOptional()
  priority?: number;

  @ApiPropertyOptional({
    description:
      'Extra metadata depending on calculation type. Examples:\n - table_rate: {"tiers":[{"upto":100,"price":"10.00"}], "measure":"subtotal"} \n - formula (simple): {"formula":"subtotal * 0.05"} \n - formula (weight surcharge): {"formula":"subtotal * 0.03 + max(0, totalWeight - 2) * 5"} \n - formula (surcharge cap): {"formula":"min(subtotal * 0.1, 50)"} \n - volumetric (example): {"formula":"max(subtotal * 0.02, (length*width*height)/5000)"} - note: volumetric variables must be provided by context',
    example: { tiers: [{ upto: 100, price: '10.00' }], measure: 'subtotal' },
  })
  @IsOptional()
  metaJson?: Record<string, unknown>;
}
