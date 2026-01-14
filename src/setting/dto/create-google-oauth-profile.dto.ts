import { ApiProperty } from '@nestjs/swagger';
import {
  ArrayNotEmpty,
  IsArray,
  IsNotEmpty,
  IsOptional,
  Matches,
  IsString,
  IsUrl,
  IsUUID,
} from 'class-validator';

export class CreateGoogleOAuthProfileDto {
  @ApiProperty({
    description:
      'Unique URL-safe key used in callback URLs (e.g. /auth/<key>/google/callback). Must be lowercase letters/numbers with dashes/underscores.',
    example: 'axis-ui',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^[a-z0-9_-]+$/, {
    message: 'key must match /^[a-z0-9_-]+$/',
  })
  key: string;

  @ApiProperty({
    description: 'Human friendly name for this Google OAuth profile',
    example: 'Customer Web OAuth',
  })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ description: 'Google OAuth client ID', example: '123.apps.googleusercontent.com' })
  @IsString()
  @IsNotEmpty()
  clientId: string;

  @ApiProperty({
    description: 'Google OAuth callback/redirect URI (must match Google Console)',
    example: 'http://localhost:5000/auth/customer/google/callback',
  })
  @IsString()
  @IsNotEmpty()
  @IsUrl({ require_tld: false })
  callbackUrl: string;

  @ApiProperty({
    description:
      'Role IDs allowed to use this profile. Descendant roles are also allowed.',
    example: ['4d2df2f7-7c14-4a5c-9ab4-6f76db0c7e5d'],
  })
  @IsArray()
  @ArrayNotEmpty()
  @IsUUID('4', { each: true })
  allowedRoleIds: string[];

  @ApiProperty({
    description:
      'Optional list of allowed email domains (e.g. ["x.com"]). If omitted/empty, any domain is allowed.',
    required: false,
    example: ['x.com'],
  })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  allowedDomains?: string[];
}
