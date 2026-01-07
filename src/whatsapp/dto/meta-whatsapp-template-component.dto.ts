import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform, Type } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsIn,
  IsNotEmpty,
  IsOptional,
  IsString,
  ValidateIf,
  ValidateNested,
} from 'class-validator';

export const META_TEMPLATE_COMPONENT_TYPES = [
  'HEADER',
  'BODY',
  'FOOTER',
  'BUTTONS',
] as const;
export type MetaTemplateComponentType =
  (typeof META_TEMPLATE_COMPONENT_TYPES)[number];

export const META_TEMPLATE_HEADER_FORMATS = [
  'TEXT',
  'IMAGE',
  'VIDEO',
  'DOCUMENT',
  'LOCATION',
] as const;
export type MetaTemplateHeaderFormat =
  (typeof META_TEMPLATE_HEADER_FORMATS)[number];

export const META_TEMPLATE_BUTTON_TYPES = [
  'QUICK_REPLY',
  'URL',
  'PHONE_NUMBER',
] as const;
export type MetaTemplateButtonType =
  (typeof META_TEMPLATE_BUTTON_TYPES)[number];

export class MetaTemplateButtonDto {
  @ApiProperty({
    description: 'Button type (Meta template schema)',
    enum: META_TEMPLATE_BUTTON_TYPES,
    example: 'QUICK_REPLY',
  })
  @IsString()
  @Transform(({ value }) =>
    typeof value === 'string' ? value.trim().toUpperCase() : value,
  )
  @IsIn(META_TEMPLATE_BUTTON_TYPES)
  type: MetaTemplateButtonType;

  @ApiPropertyOptional({
    description:
      'Button display text (required for QUICK_REPLY/URL/PHONE_NUMBER)',
    example: 'Track order',
  })
  @ValidateIf((o: MetaTemplateButtonDto) =>
    ['QUICK_REPLY', 'URL', 'PHONE_NUMBER'].includes(o.type),
  )
  @IsString()
  @IsNotEmpty()
  text?: string;

  @ApiPropertyOptional({
    description: 'URL (required when type is URL)',
    example: 'https://example.com/orders/{{1}}',
  })
  @ValidateIf((o: MetaTemplateButtonDto) => o.type === 'URL')
  @IsString()
  @IsNotEmpty()
  url?: string;

  @ApiPropertyOptional({
    description: 'Phone number (required when type is PHONE_NUMBER)',
    example: '+254700000000',
  })
  @ValidateIf((o: MetaTemplateButtonDto) => o.type === 'PHONE_NUMBER')
  @IsString()
  @IsNotEmpty()
  phone_number?: string;
}

export class MetaTemplateComponentDto {
  @ApiProperty({
    description: 'Component type (Meta template schema)',
    enum: META_TEMPLATE_COMPONENT_TYPES,
    example: 'BODY',
  })
  @IsString()
  @Transform(({ value }) =>
    typeof value === 'string' ? value.trim().toUpperCase() : value,
  )
  @IsIn(META_TEMPLATE_COMPONENT_TYPES)
  type: MetaTemplateComponentType;

  @ApiPropertyOptional({
    description: 'Header format (required when type is HEADER)',
    enum: META_TEMPLATE_HEADER_FORMATS,
    example: 'TEXT',
  })
  @ValidateIf((o: MetaTemplateComponentDto) => o.type === 'HEADER')
  @IsString()
  @Transform(({ value }) =>
    typeof value === 'string' ? value.trim().toUpperCase() : value,
  )
  @IsIn(META_TEMPLATE_HEADER_FORMATS)
  format?: MetaTemplateHeaderFormat;

  @ApiPropertyOptional({
    description: 'Text for BODY/FOOTER and TEXT headers',
    example: 'Hi {{1}}, your order {{2}} was placed successfully.',
  })
  @ValidateIf(
    (o: MetaTemplateComponentDto) =>
      o.type === 'BODY' ||
      o.type === 'FOOTER' ||
      (o.type === 'HEADER' && (o.format ?? 'TEXT') === 'TEXT'),
  )
  @IsString()
  @IsNotEmpty()
  text?: string;

  @ApiPropertyOptional({
    description: 'Buttons array (required when type is BUTTONS)',
    type: () => MetaTemplateButtonDto,
    isArray: true,
  })
  @ValidateIf((o: MetaTemplateComponentDto) => o.type === 'BUTTONS')
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(10)
  @ValidateNested({ each: true })
  @Type(() => MetaTemplateButtonDto)
  buttons?: MetaTemplateButtonDto[];
}
