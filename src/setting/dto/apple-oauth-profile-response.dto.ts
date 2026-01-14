import { ApiProperty } from '@nestjs/swagger';

export class AppleOAuthProfileResponseDto {
  @ApiProperty({ example: 'd2f1a6d6-83f3-4a9a-9bda-3b7f1a5d1c2a' })
  id: string;

  @ApiProperty({
    description:
      'Unique URL-safe key used in callback URLs (e.g. /auth/<key>/apple/callback)',
    example: 'axis-ui-apple',
    required: false,
  })
  key?: string;

  @ApiProperty({
    description:
      'Computed callback path derived from `key` (use this path when registering Apple redirect URIs).',
    example: '/auth/axis-ui-apple/apple/callback',
    required: false,
  })
  computedCallbackPath?: string;

  @ApiProperty({ example: 'Admin Apple OAuth' })
  name: string;

  @ApiProperty({ example: 'com.example.web' })
  clientId: string;

  @ApiProperty({ example: 'ABCD1234EF' })
  teamId: string;

  @ApiProperty({ example: '1A2B3C4D5E' })
  keyId: string;

  @ApiProperty({ example: 'https://api.example.com/auth/axis-admin-apple/apple/callback' })
  callbackUrl: string;

  @ApiProperty({
    description: 'Role IDs allowed to use this profile (descendants are also allowed)',
    example: ['4d2df2f7-7c14-4a5c-9ab4-6f76db0c7e5d'],
  })
  allowedRoleIds: string[];

  @ApiProperty({
    description:
      'Optional list of allowed email domains. If empty/undefined, any domain is allowed.',
    required: false,
    example: ['x.com'],
  })
  allowedDomains?: string[];

  @ApiProperty({
    description: 'Whether a private key has been stored for this profile',
    example: true,
  })
  hasPrivateKey: boolean;

  @ApiProperty({ required: false })
  createdAt?: Date;

  @ApiProperty({ required: false })
  updatedAt?: Date;
}
