import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString, IsUUID, Length } from 'class-validator';

export class CreateShippingZoneLocationDto {
  @ApiProperty({ description: 'Shipping zone id (UUID)' })
  @IsUUID()
  zoneId: string;

  @ApiProperty({ description: 'Location id (UUID) to attach this zone to' })
  @IsUUID()
  locationId: string;

  @ApiPropertyOptional({
    description:
      'Destination country ISO2 code. If omitted, the API will infer it from the referenced Location when possible.',
    example: 'KE',
  })
  @IsOptional()
  @IsString()
  @Length(2, 2)
  countryCode?: string;

  @ApiPropertyOptional({
    description:
      "Optional type (defaults to 'location'). Legacy types exist for backward compatibility.",
    example: 'location',
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  type?: string;
}
