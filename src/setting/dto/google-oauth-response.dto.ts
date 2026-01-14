import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class GoogleOAuthResponseDto {
  @ApiProperty({ example: '1234567890-abc123def456.apps.googleusercontent.com' })
  clientId: string;

  @ApiPropertyOptional({ example: 'https://api.example.com/api/auth/google/callback' })
  callbackUrl?: string;

  @ApiProperty({
    description:
      'Whether a client secret has been stored (secret value is never returned).',
  })
  hasClientSecret: boolean;

  @ApiPropertyOptional()
  createdAt?: Date;

  @ApiPropertyOptional()
  updatedAt?: Date;
}
// Legacy: Use Google OAuth profiles instead
