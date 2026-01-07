import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString, IsBoolean, IsUUID } from 'class-validator';

export class CreateShippingMethodDto {
  @ApiPropertyOptional({
    description:
      'Provider id (shipping_provider). If omitted, provider text may be used (legacy).',
  })
  @IsOptional()
  @IsUUID()
  providerId?: string;

  @ApiProperty({
    description: 'Unique code for the method',
    example: 'standard',
  })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({ description: 'Display name', example: 'Standard Shipping' })
  @IsString()
  @IsNotEmpty()
  displayName: string;

  @ApiPropertyOptional({ description: 'Provider name' })
  @IsOptional()
  @IsString()
  provider?: string;

  @ApiPropertyOptional({ description: 'Is active' })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}
