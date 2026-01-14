import { ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsOptional,
  IsString,
  IsUrl,
  IsUUID,
  Matches,
} from 'class-validator';

export class UpdateGoogleOAuthProfileDto {
  @ApiPropertyOptional({
    description:
      'Unique URL-safe key used in callback URLs (e.g. /auth/<key>/google/callback). Must be lowercase letters/numbers with dashes/underscores.',
    example: 'axis-ui',
  })
  @IsString()
  @IsOptional()
  @Matches(/^[a-z0-9_-]+$/, {
    message: 'key must match /^[a-z0-9_-]+$/',
  })
  key?: string;

  @ApiPropertyOptional({
    description: 'Human friendly name for this Google OAuth profile',
    example: 'Customer Web OAuth',
  })
  @IsString()
  @IsOptional()
  name?: string;

  @ApiPropertyOptional({
    description: 'Google OAuth client ID',
    example: '123.apps.googleusercontent.com',
  })
  @IsString()
  @IsOptional()
  clientId?: string;

  @ApiPropertyOptional({
    description: 'Google OAuth callback/redirect URI',
    example: 'http://localhost:5000/auth/customer/google/callback',
  })
  @IsString()
  @IsOptional()
  @IsUrl({ require_tld: false })
  callbackUrl?: string;

  @ApiPropertyOptional({
    description:
      'Role IDs allowed to use this profile. Descendant roles are also allowed.',
    example: ['4d2df2f7-7c14-4a5c-9ab4-6f76db0c7e5d'],
  })
  @IsArray()
  @IsOptional()
  @IsUUID('4', { each: true })
  allowedRoleIds?: string[];

  @ApiPropertyOptional({
    description:
      'Optional list of allowed email domains (e.g. ["x.com"]). If omitted/empty, any domain is allowed.',
    example: ['x.com'],
  })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  allowedDomains?: string[];
}
