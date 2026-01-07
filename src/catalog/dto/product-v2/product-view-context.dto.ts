import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class ProductViewContextDto {
  @ApiPropertyOptional({
    description: 'Channel code (e.g. WEB, MOBILE, WHATSAPP)',
  })
  @IsOptional()
  @IsString()
  channel?: string;

  @ApiPropertyOptional({
    description: 'Customer tier/segment (e.g. VIP, REGULAR)',
  })
  @IsOptional()
  @IsString()
  customerTier?: string;

  @ApiPropertyOptional({ description: 'Location identifier (e.g. KE-NBI)' })
  @IsOptional()
  @IsString()
  location?: string;

  @ApiPropertyOptional({
    description: 'Role identifier (e.g. agent, admin, customer)',
  })
  @IsOptional()
  @IsString()
  role?: string;
}
