import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsInt,
  IsObject,
  IsOptional,
  IsString,
  ValidateNested,
} from 'class-validator';

class RuleExpressionDto {
  @ApiProperty({ enum: ['EXPRESSION', 'SCRIPT'] })
  @IsString()
  type: 'EXPRESSION' | 'SCRIPT';

  @ApiPropertyOptional({ enum: ['CEL', 'JSONLOGIC'] })
  @IsOptional()
  @IsString()
  language?: 'CEL' | 'JSONLOGIC';

  @ApiProperty({
    description:
      'Expression string. For JSONLOGIC this should be a JSON string.',
  })
  @IsString()
  expression: string;
}

class ContextMatchDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  channel?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  customerTier?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  location?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  role?: string;
}

export class CreateProductContextOverrideDto {
  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({ default: 0 })
  @IsOptional()
  @IsInt()
  @Type(() => Number)
  priority?: number;

  @ApiPropertyOptional({
    description: 'ISO timestamp when this override becomes active',
  })
  @IsOptional()
  @IsString()
  validFrom?: string;

  @ApiPropertyOptional({
    description: 'ISO timestamp when this override expires',
  })
  @IsOptional()
  @IsString()
  validUntil?: string;

  @ApiPropertyOptional({ type: () => ContextMatchDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ContextMatchDto)
  match?: ContextMatchDto;

  @ApiPropertyOptional({ type: () => RuleExpressionDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => RuleExpressionDto)
  rule?: RuleExpressionDto;

  @ApiProperty({
    description:
      'JSON Patch operations (RFC 6902) applied to the ProductDTO when matched',
    isArray: true,
    example: [{ op: 'replace', path: '/pricing/basePrice', value: 999 }],
  })
  @IsArray()
  @IsObject({ each: true })
  patch: Array<Record<string, unknown>>;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  description?: string;
}
