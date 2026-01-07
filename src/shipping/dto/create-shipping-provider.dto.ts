import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateShippingProviderDto {
  @ApiProperty({ description: 'Unique provider code', example: 'internal' })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({ description: 'Display name', example: 'Internal Fleet' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiPropertyOptional({ description: 'Is active' })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({ description: 'Provider metadata' })
  @IsOptional()
  metaJson?: Record<string, unknown>;
}
