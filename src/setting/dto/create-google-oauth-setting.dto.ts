import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsUrl, MaxLength } from 'class-validator';

export class CreateGoogleOAuthSettingDto {
  @ApiProperty({ example: '1234567890-abc123def456.apps.googleusercontent.com' })
  @IsString()
  @MaxLength(512)
  clientId: string;

  @ApiPropertyOptional({
    description:
      'Optional override for the callback URL. If omitted, the app default callback URL is used.',
    example: 'https://api.example.com/api/auth/google/callback',
  })
  @IsOptional()
  @IsUrl({ require_tld: false })
  @MaxLength(1024)
  callbackUrl?: string;
}
// Legacy: Use Google OAuth profiles instead
