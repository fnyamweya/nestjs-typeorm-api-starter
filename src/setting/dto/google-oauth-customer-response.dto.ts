import { ApiProperty } from '@nestjs/swagger';

export class GoogleOAuthCustomerResponseDto {
  @ApiProperty({ example: '1234567890-abc123def456.apps.googleusercontent.com' })
  clientId: string;

  @ApiProperty({
    example: 'http://localhost:5000/auth/customer/google/callback',
    required: false,
  })
  callbackUrl?: string;

  @ApiProperty({
    description: 'Whether a client secret is stored (encrypted) in settings',
    example: true,
  })
  hasClientSecret: boolean;

  @ApiProperty({ required: false })
  createdAt?: Date;

  @ApiProperty({ required: false })
  updatedAt?: Date;
}
// Legacy: Use Google OAuth profiles instead
