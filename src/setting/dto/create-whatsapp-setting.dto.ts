import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsIn,
  IsNotEmpty,
  IsOptional,
  IsString,
} from 'class-validator';

export class CreateWhatsappSettingDto {
  @ApiProperty({
    description: 'WhatsApp Business API provider',
    example: 'meta',
    enum: ['meta'],
    default: 'meta',
  })
  @IsString({ message: 'Provider must be a string' })
  @IsIn(['meta'], { message: 'Only meta provider is supported currently' })
  provider: string = 'meta';

  @ApiProperty({
    description: 'Meta access token for the WhatsApp Business API',
    example: 'EAABsbCS1iHgBA...',
  })
  @IsString({ message: 'Access token must be a string' })
  @IsNotEmpty({ message: 'Access token is required' })
  accessToken: string;

  @ApiProperty({
    description: 'WhatsApp Business Account ID',
    example: '123456789012345',
  })
  @IsString({ message: 'Business account ID must be a string' })
  @IsNotEmpty({ message: 'Business account ID is required' })
  businessAccountId: string;

  @ApiProperty({
    description: 'WhatsApp phone number ID',
    example: '109876543210987',
  })
  @IsString({ message: 'Phone number ID must be a string' })
  @IsNotEmpty({ message: 'Phone number ID is required' })
  phoneNumberId: string;

  @ApiPropertyOptional({
    description: 'Meta app ID (optional)',
    example: '1234567890',
  })
  @IsOptional()
  @IsString({ message: 'App ID must be a string' })
  appId?: string;

  @ApiPropertyOptional({
    description: 'API version to use',
    example: 'v19.0',
    default: 'v19.0',
  })
  @IsOptional()
  @IsString({ message: 'API version must be a string' })
  apiVersion?: string;

  @ApiPropertyOptional({
    description: 'Override base URL for WhatsApp Business API',
    example: 'https://graph.facebook.com',
  })
  @IsOptional()
  @IsString({ message: 'Base URL must be a string' })
  baseUrl?: string;

  @ApiProperty({
    description: 'Enable or disable WhatsApp delivery',
    example: true,
  })
  @IsBoolean({ message: 'whatsappEnabled must be a boolean' })
  whatsappEnabled: boolean;
}
