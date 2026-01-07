import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsIn,
  IsInt,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  Length,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';

const PRICE_LIST_STATUS = ['active', 'inactive', 'archived'] as const;
const STACKING_POLICY = ['EXCLUSIVE', 'STACKABLE'] as const;
const MATCH_POLICY = [
  'HIGHEST_PRIORITY',
  'LOWEST_PRICE',
  'FIRST_MATCH',
] as const;

export class CreatePriceListDto {
  @ApiProperty({ description: 'Unique price list code', example: 'ke-retail' })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({ description: 'Display name', example: 'Kenya Retail' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ description: 'Currency (ISO3)', example: 'KES' })
  @IsString()
  @Length(3, 3)
  currency: string;

  @ApiPropertyOptional({
    description: 'Priority (higher wins by default)',
    example: 10,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  priority?: number;

  @ApiPropertyOptional({
    description:
      'Dynamic scope selector. Can store channel/country/customer segment/etc without schema changes.',
    example: { countryCode: 'KE', channel: 'web' },
  })
  @IsOptional()
  @IsObject()
  scope?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Status',
    enum: PRICE_LIST_STATUS,
    example: 'active',
  })
  @IsOptional()
  @IsIn(PRICE_LIST_STATUS as unknown as string[])
  status?: string;

  @ApiPropertyOptional({
    description: 'Stacking policy',
    enum: STACKING_POLICY,
    example: 'EXCLUSIVE',
  })
  @IsOptional()
  @IsIn(STACKING_POLICY as unknown as string[])
  stackingPolicy?: string;

  @ApiPropertyOptional({
    description: 'Match policy',
    enum: MATCH_POLICY,
    example: 'HIGHEST_PRIORITY',
  })
  @IsOptional()
  @IsIn(MATCH_POLICY as unknown as string[])
  matchPolicy?: string;

  @ApiPropertyOptional({
    description: 'Stop after first match (when evaluating rows)',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  stopAfterMatch?: boolean;
}
