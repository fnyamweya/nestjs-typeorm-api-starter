import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString, IsUUID } from 'class-validator';

export class AttachShippingZoneLocationDto {
  @ApiProperty({ description: 'Location id (UUID) to attach this zone to' })
  @IsUUID()
  locationId: string;

  @ApiPropertyOptional({
    description: "Optional type (defaults to 'location'). Legacy types exist for backward compatibility.",
    example: 'location',
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  type?: string;
}
