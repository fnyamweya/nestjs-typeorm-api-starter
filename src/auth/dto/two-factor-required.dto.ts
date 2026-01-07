import { ApiProperty } from '@nestjs/swagger';

export class TwoFactorRequiredDto {
  @ApiProperty({
    description: 'Whether 2FA step-up is required',
    example: true,
  })
  requiresTwoFactor: true;

  @ApiProperty({
    description: 'User identifier for legacy compatibility',
    example: '1ab0c8f0-7d3a-4f5f-80ab-e3f98cd5ef70',
    format: 'uuid',
  })
  userId: string;

  @ApiProperty({
    description:
      'Signed short-lived token to verify the OTP without sending raw userId (recommended)',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  twoFactorToken: string;

  @ApiProperty({
    description: 'Human-readable message',
    example: 'Two-factor authentication code queued for delivery',
  })
  message: string;
}
