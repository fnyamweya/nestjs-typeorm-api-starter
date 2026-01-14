import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString, IsUrl } from 'class-validator';

export class CreateGoogleOAuthCustomerSettingDto {
  @ApiProperty({ example: '1234567890-abc123def456.apps.googleusercontent.com' })
  @IsString()
  @IsNotEmpty()
  clientId: string;

  @ApiProperty({
    example: 'http://localhost:5000/auth/customer/google/callback',
    required: false,
  })
  @IsOptional()
  @IsUrl({ require_tld: false })
  callbackUrl?: string;
}
// Legacy: Use Google OAuth profiles instead
