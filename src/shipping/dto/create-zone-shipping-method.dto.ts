import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateZoneShippingMethodDto {
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
