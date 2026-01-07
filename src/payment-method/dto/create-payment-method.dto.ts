import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ArrayUnique,
  IsArray,
  IsBoolean,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
} from 'class-validator';

export class CreatePaymentMethodDto {
  @ApiProperty({ description: 'Unique payment method code', example: 'MPESA' })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({ description: 'Payment provider id (FK)', format: 'uuid' })
  @IsUUID()
  @IsNotEmpty()
  providerId: string;

  @ApiProperty({ description: 'Payment method name', example: 'M-Pesa' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiPropertyOptional({ description: 'Payment method description' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({
    description: 'Whether method is active',
    default: true,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({
    description:
      'Channel codes that may use this payment method (preferred field)',
    example: ['WEB', 'MOBILE', 'WHATSAPP'],
    type: [String],
  })
  @IsOptional()
  @IsArray()
  @ArrayUnique()
  @IsString({ each: true })
  channelCodes?: string[];

  @ApiPropertyOptional({
    description:
      'Channel codes that may use this payment method (deprecated alias of channelCodes)',
    example: ['WEB', 'MOBILE', 'WHATSAPP'],
    type: [String],
    deprecated: true,
  })
  @IsOptional()
  @IsArray()
  @ArrayUnique()
  @IsString({ each: true })
  channels?: string[];

  @ApiPropertyOptional({
    description:
      'Optional country scoping (ISO-3166 alpha-2). Empty means not restricted.',
    example: ['KE'],
    type: [String],
  })
  @IsOptional()
  @IsArray()
  @ArrayUnique()
  @IsString({ each: true })
  countryCodes?: string[];

  @ApiPropertyOptional({
    description:
      'Optional currency scoping (ISO-4217). Empty means not restricted.',
    example: ['KES'],
    type: [String],
  })
  @IsOptional()
  @IsArray()
  @ArrayUnique()
  @IsString({ each: true })
  currencyCodes?: string[];

  @ApiPropertyOptional({
    description: 'Arbitrary configuration JSON (dynamic)',
    type: 'object',
    additionalProperties: true,
  })
  @IsOptional()
  @IsObject()
  configJson?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Arbitrary metadata JSON (dynamic)',
    type: 'object',
    additionalProperties: true,
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;
}
