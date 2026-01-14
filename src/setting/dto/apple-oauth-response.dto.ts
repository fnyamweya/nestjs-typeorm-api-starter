import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class AppleOAuthResponseDto {
  @ApiProperty({ description: 'Apple Services ID (client ID).' })
  clientId: string;

  @ApiProperty({ description: 'Apple Developer Team ID.' })
  teamId: string;

  @ApiProperty({ description: 'Apple Key ID.' })
  keyId: string;

  @ApiPropertyOptional({ example: 'https://api.example.com/api/auth/apple/callback' })
  callbackUrl?: string;

  @ApiProperty({
    description:
      'Whether an Apple private key has been stored (secret value is never returned).',
  })
  hasPrivateKey: boolean;

  @ApiPropertyOptional()
  createdAt?: Date;

  @ApiPropertyOptional()
  updatedAt?: Date;
}
