import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsObject, IsOptional, IsString } from 'class-validator';

export class UpdatePaymentProviderDto {
  @ApiPropertyOptional({
    description: 'Unique provider code',
    example: 'SAFARICOM',
  })
  @IsOptional()
  @IsString()
  code?: string;

  @ApiPropertyOptional({ description: 'Provider name', example: 'Safaricom' })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({ description: 'Provider description' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ description: 'Whether provider is active' })
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
