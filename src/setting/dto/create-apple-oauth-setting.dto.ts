import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsUrl, MaxLength } from 'class-validator';

export class CreateAppleOAuthSettingDto {
  @ApiProperty({ description: 'Apple Services ID (client ID).' })
  @IsString()
  @MaxLength(512)
  clientId: string;

  @ApiProperty({ description: 'Apple Developer Team ID.' })
  @IsString()
  @MaxLength(64)
  teamId: string;

  @ApiProperty({ description: 'Apple Key ID.' })
  @IsString()
  @MaxLength(64)
  keyId: string;

  @ApiPropertyOptional({
    description:
      'Optional override for the callback URL. If omitted, the app default callback URL is used.',
    example: 'https://api.example.com/api/auth/apple/callback',
  })
  @IsOptional()
  @IsUrl({ require_tld: false })
  @MaxLength(1024)
  callbackUrl?: string;
}
