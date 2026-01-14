import { ApiProperty } from '@nestjs/swagger';

export class GoogleOAuthProfileResponseDto {
  @ApiProperty({ example: 'd2f1a6d6-83f3-4a9a-9bda-3b7f1a5d1c2a' })
  id: string;

  @ApiProperty({
    description:
      'Unique URL-safe key used in callback URLs (e.g. /auth/<key>/google/callback)',
    example: 'axis-ui',
    required: false,
  })
  key?: string;

  @ApiProperty({
    description:
      'Computed callback path derived from `key` (use this path when registering Google redirect URIs).',
    example: '/auth/axis-ui/google/callback',
    required: false,
  })
  computedCallbackPath?: string;

  @ApiProperty({ example: 'Customer Web OAuth' })
  name: string;

  @ApiProperty({ example: '123.apps.googleusercontent.com' })
  clientId: string;

  @ApiProperty({ example: 'http://localhost:5000/auth/customer/google/callback' })
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
    description: 'Whether a client secret has been stored for this profile',
    example: true,
  })
  hasClientSecret: boolean;

  @ApiProperty({ required: false })
  createdAt?: Date;

  @ApiProperty({ required: false })
  updatedAt?: Date;
}
