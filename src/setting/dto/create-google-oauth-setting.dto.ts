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
    example: 'https://api.example.com/api/auth/admin/google/callback',
  })
  @IsOptional()
  @IsUrl()
  @MaxLength(1024)
  callbackUrl?: string;
}
