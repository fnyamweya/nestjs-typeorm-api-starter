import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsArray, IsNotEmpty, IsOptional, IsString, IsUUID, Length } from 'class-validator';

export class CreateMethodShippingRateDto {
  @ApiProperty({
    description: 'Calculation type',
    example: 'flat',
    enum: ['flat', 'per_weight', 'per_item', 'table_rate', 'formula'],
  })
  @IsString()
  @IsNotEmpty()
  calculationType:
    | 'flat'
    | 'per_weight'
    | 'per_item'
    | 'table_rate'
    | 'formula';

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

  @ApiPropertyOptional({
    description: 'Price per unit (for per_weight or per_item)',
  })
  @IsOptional()
  pricePerUnit?: string;

  @ApiPropertyOptional({
    description: 'Priority (higher number = higher priority)',
  })
  @IsOptional()
  priority?: number;

  @ApiPropertyOptional({
    description:
      'Optional currency code (ISO 4217, e.g., KES). If set, this rate only applies to that currency.',
    example: 'KES',
  })
  @IsOptional()
  @IsString()
  @Length(3, 3)
  currencyCode?: string;

  @ApiPropertyOptional({
    description:
      'Optional channel targeting. If provided, this rate only applies to the given channels.',
    type: [String],
  })
  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  channelIds?: string[];

  @ApiPropertyOptional({
    description:
      'Extra metadata depending on calculation type. Examples:\n - table_rate: {"tiers":[{"upto":100,"price":"10.00"}], "measure":"subtotal"}\n - formula: {"formula":"subtotal * 0.05"}\n\nOptional targeting (so rates can apply to specific catalog entities):\n - productIds: ["<uuid>"]\n - categoryIds: ["<uuid>"]\n - taxonomyIds: ["<uuid>"]\n\nTargeted rates get a priority boost vs non-targeted rates (product > category > taxonomy).',
  })
  @IsOptional()
  metaJson?: Record<string, unknown>;
}
