import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class ProductTranslationDto {
  @ApiProperty({ description: 'IETF locale code', example: 'en' })
  @IsString()
  locale: string;

  @ApiProperty({ description: 'Localized product title', example: 'iPhone 15' })
  @IsString()
  title: string;

  @ApiPropertyOptional({ description: 'Localized product description' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({
    description: 'Arbitrary translation metadata',
    example: { tagline: 'New' },
  })
  @IsOptional()
  metaJson?: Record<string, unknown>;
}
