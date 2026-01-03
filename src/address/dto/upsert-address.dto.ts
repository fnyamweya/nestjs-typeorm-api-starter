import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  Length,
} from 'class-validator';

export class UpsertAddressDto {
  @ApiPropertyOptional({ description: 'Recipient first name' })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  firstName?: string;

  @ApiPropertyOptional({ description: 'Recipient last name' })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  lastName?: string;

  @ApiPropertyOptional({ description: 'Phone number for delivery/contact' })
  @IsOptional()
  @IsString()
  phone?: string;

  @ApiProperty({ description: 'Country ISO2 code', example: 'KE' })
  @IsString()
  @IsNotEmpty()
  @Length(2, 2)
  countryCode: string;

  @ApiPropertyOptional({
    description:
      'Most-specific selected location id (UUID). Use /api/v1/locations to browse the parent->child hierarchy.',
  })
  @IsOptional()
  @IsUUID()
  locationId?: string;

  @ApiPropertyOptional({
    description:
      'Dynamic address fields (country-specific). Fetch schema via /api/v1/addresses/field-config?countryCode=KE',
  })
  @IsOptional()
  @IsObject()
  fields?: Record<string, unknown>;

  @ApiPropertyOptional({
    description:
      'Optional Google Place ID. If provided, the backend will fetch place details and populate fields from Google data (stored in fields.google).',
    example: 'ChIJN1t_tDeuEmsRUsoyG83frY4',
  })
  @IsOptional()
  @IsString()
  googlePlaceId?: string;

  @ApiPropertyOptional({
    description:
      'Optional Google Places session token used during autocomplete/details. Helps Google billing + consistency.',
  })
  @IsOptional()
  @IsString()
  googleSessionToken?: string;
}
