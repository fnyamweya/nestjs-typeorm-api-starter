import { ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsOptional,
  IsString,
  IsUrl,
  IsUUID,
  Matches,
} from 'class-validator';

export class UpdateAppleOAuthProfileDto {
  @ApiPropertyOptional({
    description:
      'Unique URL-safe key used in callback URLs (e.g. /auth/<key>/apple/callback). Must be lowercase letters/numbers with dashes/underscores.',
    example: 'axis-ui-apple',
  })
  @IsString()
  @IsOptional()
  @Matches(/^[a-z0-9_-]+$/, {
    message: 'key must match /^[a-z0-9_-]+$/',
  })
  key?: string;

  @ApiPropertyOptional({ description: 'Human friendly name' })
  @IsString()
  @IsOptional()
  name?: string;

  @ApiPropertyOptional({ description: 'Apple Services ID (clientID)' })
  @IsString()
  @IsOptional()
  clientId?: string;

  @ApiPropertyOptional({ description: 'Apple team ID' })
  @IsString()
  @IsOptional()
  teamId?: string;

  @ApiPropertyOptional({ description: 'Apple key ID' })
  @IsString()
  @IsOptional()
  keyId?: string;

  @ApiPropertyOptional({
    description: 'Apple OAuth callback/redirect URI',
    example: 'https://api.example.com/auth/axis-ui-apple/apple/callback',
  })
  @IsString()
  @IsOptional()
  @IsUrl({ require_tld: false })
  callbackUrl?: string;

  @ApiPropertyOptional({
    description:
      'Role IDs allowed to use this profile. Descendant roles are also allowed.',
  })
  @IsArray()
  @IsOptional()
  @IsUUID('4', { each: true })
  allowedRoleIds?: string[];

  @ApiPropertyOptional({
    description:
      'Optional list of allowed email domains (e.g. ["x.com"]). If omitted/empty, any domain is allowed.',
  })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  allowedDomains?: string[];
}
