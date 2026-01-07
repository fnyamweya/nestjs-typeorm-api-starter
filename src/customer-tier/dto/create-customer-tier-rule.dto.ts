import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsInt,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  Min,
} from 'class-validator';

export class CreateCustomerTierRuleDto {
  @ApiProperty()
  @IsUUID()
  tierId: string;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({ example: 0 })
  @IsOptional()
  @IsInt()
  @Min(0)
  priority?: number;

  @ApiPropertyOptional({ description: 'ISO datetime' })
  @IsOptional()
  @IsString()
  validFrom?: string;

  @ApiPropertyOptional({ description: 'ISO datetime' })
  @IsOptional()
  @IsString()
  validUntil?: string;

  @ApiProperty({
    description:
      'JSONLogic rule to determine if this tier applies for the customer facts',
    type: Object,
  })
  @IsObject()
  @IsNotEmpty()
  rule: Record<string, unknown>;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;
}
