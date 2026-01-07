import { ApiPropertyOptional } from '@nestjs/swagger';
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

export class UpdatePriceListDto {
  @ApiPropertyOptional({
    description: 'Unique price list code',
    example: 'ke-retail',
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  code?: string;

  @ApiPropertyOptional({ description: 'Display name', example: 'Kenya Retail' })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  name?: string;

  @ApiPropertyOptional({ description: 'Currency (ISO3)', example: 'KES' })
  @IsOptional()
  @IsString()
  @Length(3, 3)
  currency?: string;

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
    description: 'Dynamic scope selector (JSON).',
    example: { countryCode: 'KE', channel: 'web' },
  })
  @IsOptional()
  @IsObject()
  scope?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Status',
    enum: PRICE_LIST_STATUS,
    example: 'inactive',
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

  @ApiPropertyOptional({ description: 'Stop after first match', example: true })
  @IsOptional()
  @IsBoolean()
  stopAfterMatch?: boolean;
}
