import { ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsObject,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

export class UpdateChannelDto {
  @ApiPropertyOptional({
    description:
      'Stable identifier used by integrations and orders (stored uppercase).',
    example: 'WEB',
  })
  @IsOptional()
  @IsString()
  @MinLength(2)
  @MaxLength(64)
  @Matches(/^[A-Za-z0-9][A-Za-z0-9_-]*$/)
  code?: string;

  @ApiPropertyOptional({ example: 'Web Store' })
  @IsOptional()
  @IsString()
  @MinLength(2)
  @MaxLength(120)
  name?: string;

  @ApiPropertyOptional({ example: 'Primary ecommerce storefront channel.' })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;

  @ApiPropertyOptional({ description: 'Whether this channel is active.' })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({
    description:
      'Arbitrary JSON configuration for this channel (e.g. integration settings, storefront rules).',
    example: { currencyCode: 'KES', locale: 'en-KE' },
  })
  @IsOptional()
  @IsObject()
  configJson?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: 'Additional metadata for internal use.',
    example: { storefront: true },
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;
}
