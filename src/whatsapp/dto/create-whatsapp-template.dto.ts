import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform, Type } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsIn,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  ValidateNested,
  registerDecorator,
  ValidationArguments,
  ValidationOptions,
} from 'class-validator';

import { MetaTemplateComponentDto } from './meta-whatsapp-template-component.dto';

const TEMPLATE_CATEGORIES = ['AUTHENTICATION', 'MARKETING', 'UTILITY'] as const;

function tryParseJson(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  if (!trimmed) return value;
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

function coerceJsonArray(value: unknown): unknown {
  const parsed = tryParseJson(value);
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(value)) return value.map(tryParseJson);
  return parsed;
}

function IsObjectArray(validationOptions?: ValidationOptions) {
  return (target: object, propertyName: string) => {
    registerDecorator({
      name: 'isObjectArray',
      target: (target as any).constructor,
      propertyName,
      options: validationOptions,
      validator: {
        validate(value: unknown) {
          if (!Array.isArray(value)) return false;
          return value.every(
            (item) =>
              typeof item === 'object' && item !== null && !Array.isArray(item),
          );
        },
        defaultMessage(args: ValidationArguments) {
          return `each value in ${args.property} must be an object`;
        },
      },
    });
  };
}

export class CreateWhatsappTemplateDto {
  @ApiProperty({
    description: 'Template name (must match WhatsApp constraints)',
    example: 'order_confirmation',
  })
  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  name: string;

  @ApiPropertyOptional({
    description: 'Template language code',
    example: 'en_US',
    default: 'en_US',
  })
  @IsOptional()
  @IsString()
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  language?: string;

  @ApiProperty({
    description: 'WhatsApp template category',
    example: 'UTILITY',
    enum: TEMPLATE_CATEGORIES,
  })
  @IsString()
  @Transform(({ value }) =>
    typeof value === 'string' ? value.trim().toUpperCase() : value,
  )
  @IsIn(TEMPLATE_CATEGORIES)
  category: string;

  @ApiProperty({
    description: 'Template components payload (Meta template schema)',
    type: () => MetaTemplateComponentDto,
    isArray: true,
  })
  @Transform(({ value }) => coerceJsonArray(value))
  @Type(() => MetaTemplateComponentDto)
  @IsArray()
  @ValidateNested({ each: true })
  components: MetaTemplateComponentDto[];

  @ApiPropertyOptional({
    description:
      'Default send-time components (message payload shape, not the Meta template schema). Stored locally for convenience.',
    type: 'array',
    items: {
      type: 'object',
      example: {
        type: 'body',
        parameters: [{ type: 'text', text: 'Customer' }],
      },
    },
  })
  @IsOptional()
  @Transform(({ value }) => coerceJsonArray(value))
  @IsArray()
  @IsObjectArray()
  defaultComponents?: Array<Record<string, unknown>>;

  @ApiPropertyOptional({
    description: 'Activate or deactivate template',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({
    description: 'Extra metadata for business logic',
    example: { scenario: 'order-confirmed' },
  })
  @IsOptional()
  @IsObject()
  metaJson?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Immediately submit template to WhatsApp provider',
    example: false,
  })
  @IsOptional()
  @IsBoolean()
  submitToProvider?: boolean;
}
