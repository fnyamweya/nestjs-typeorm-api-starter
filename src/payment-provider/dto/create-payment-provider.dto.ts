import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
} from 'class-validator';

export class CreatePaymentProviderDto {
  @ApiProperty({ description: 'Unique provider code', example: 'SAFARICOM' })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({ description: 'Provider name', example: 'Safaricom' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiPropertyOptional({ description: 'Provider description' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({
    description: 'Whether provider is active',
    default: true,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

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
