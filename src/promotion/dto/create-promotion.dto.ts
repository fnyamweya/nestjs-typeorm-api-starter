import {
  IsArray,
  IsDateString,
  IsInt,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  ValidateNested,
  IsEnum,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  ConditionOperator,
  PromotionActionType,
  PromotionConditionType,
  PromotionStatus,
  StackingPolicy,
} from '../entities/promotion.enums';

class CreatePromotionConditionDto {
  @ApiProperty({
    enum: PromotionConditionType,
    description: 'Condition type to evaluate against the order context.',
    example: PromotionConditionType.ITEM_IN_PRODUCT,
  })
  @IsEnum(PromotionConditionType)
  type: PromotionConditionType;

  @ApiProperty({
    enum: ConditionOperator,
    description:
      "Operator used to compare order context with params. For item targeting conditions, use: 'eq' | 'in' | 'contains' to require a match, and 'neq' | 'not_in' to require no match.",
    example: ConditionOperator.IN,
  })
  @IsEnum(ConditionOperator)
  operator: ConditionOperator;

  @ApiProperty({
    description:
      'Condition parameters. For item targeting conditions, the engine accepts multiple aliases to make admin UIs simpler.\n\nSupported shapes:\n- item_in_product: { productIds: [uuid] } OR { productId: uuid } OR { ids: [uuid] } OR { id: uuid }\n- item_in_category: { categoryIds: [uuid] } OR { categoryId: uuid } (also supports ids/id)\n- item_in_taxonomy: { taxonomyIds: [uuid] } OR { taxonomyId: uuid } (also supports ids/id)\n- item_has_tag: { tags: [string] } OR { tag: string } (also supports ids/id)\n\nNotes:\n- IDs are treated as strings; empty arrays never match.\n- With item targeting, promotions will NOT apply if the order context does not include items.',
    examples: {
      item_in_product: {
        value: { productIds: ['3a3d0e5e-5b69-4c1f-8df3-7a6d7c2c0b11'] },
      },
      item_in_category: {
        value: { categoryIds: ['9b2d2c8b-1a24-4f64-a1e6-0e8c1c3c9d10'] },
      },
      item_in_taxonomy: {
        value: { taxonomyIds: ['1f64a1e6-0e8c-4f64-a1e6-0e8c1c3c9d10'] },
      },
      item_has_tag: { value: { tags: ['clearance', 'vip'] } },
    },
  })
  @IsObject()
  params: Record<string, unknown>;
}

class CreatePromotionActionDto {
  @ApiProperty({
    enum: PromotionActionType,
    description: 'Action type to apply when all conditions match.',
    example: PromotionActionType.PERCENT_OFF,
  })
  @IsEnum(PromotionActionType)
  type: PromotionActionType;

  @ApiProperty({
    description:
      "Action parameters. Examples:\n- percent_off: { percent: 10 }\n- fixed_off: { amount: 500, currency: 'KES' }\n- free_shipping: {}",
    example: { percent: 10 },
  })
  @IsObject()
  params: Record<string, unknown>;

  @ApiPropertyOptional({
    description:
      "Optional targeting for the action. Current engine defaults to order-level scope when omitted. Example: { scope: 'order' }",
    example: { scope: 'order' },
  })
  @IsOptional()
  @IsObject()
  target?: Record<string, unknown>;
}

export class CreatePromotionDto {
  @ApiProperty({ description: 'Unique promotion code', example: 'WELCOME10' })
  @IsNotEmpty()
  code: string;

  @ApiPropertyOptional({
    description: 'Display name for admins',
    example: 'Welcome discount',
  })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({
    description: 'Optional description',
    example: '10% off for first-time customers',
  })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({
    enum: PromotionStatus,
    example: PromotionStatus.ACTIVE,
  })
  @IsOptional()
  @IsEnum(PromotionStatus)
  status?: PromotionStatus;

  @ApiPropertyOptional({
    description: 'Priority (lower runs first)',
    example: 100,
  })
  @IsOptional()
  @IsInt()
  priority?: number;

  @ApiPropertyOptional({
    enum: StackingPolicy,
    example: StackingPolicy.STACKABLE,
  })
  @IsOptional()
  @IsEnum(StackingPolicy)
  stackingPolicy?: StackingPolicy;

  @ApiPropertyOptional({
    description: 'Optional stacking group key',
    example: 'welcome',
  })
  @IsOptional()
  @IsString()
  stackingGroup?: string;

  @ApiPropertyOptional({ description: 'Global max redemptions', example: 1000 })
  @IsOptional()
  @IsInt()
  maxRedemptions?: number;

  @ApiPropertyOptional({
    description: 'Max redemptions per customer',
    example: 1,
  })
  @IsOptional()
  @IsInt()
  maxRedemptionsPerCustomer?: number;

  @ApiPropertyOptional({
    description: 'ISO date-time when the promo becomes valid',
    example: '2026-01-01T00:00:00.000Z',
  })
  @IsOptional()
  @IsDateString()
  validFrom?: string;

  @ApiPropertyOptional({
    description: 'ISO date-time when the promo expires',
    example: '2026-12-31T23:59:59.999Z',
  })
  @IsOptional()
  @IsDateString()
  validTo?: string;

  @ApiPropertyOptional({
    description: 'Optional channel allow-list',
    example: ['web', 'pos'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  channels?: string[];

  @ApiPropertyOptional({
    description: 'Optional metadata blob (admin-only)',
    example: { note: 'created by ops' },
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;

  @ApiPropertyOptional({
    type: CreatePromotionConditionDto,
    isArray: true,
    description:
      'All conditions must match (logical AND). Omit or pass [] for unconditional promotions.',
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreatePromotionConditionDto)
  conditions?: CreatePromotionConditionDto[];

  @ApiProperty({
    type: CreatePromotionActionDto,
    isArray: true,
    description:
      'Actions to apply when conditions match. At least one action is required.',
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreatePromotionActionDto)
  actions: CreatePromotionActionDto[];
}
