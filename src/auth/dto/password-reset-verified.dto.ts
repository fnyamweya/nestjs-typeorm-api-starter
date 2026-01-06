import { ApiProperty } from '@nestjs/swagger';

export class PasswordResetVerifiedDto {
  @ApiProperty({
    description: 'Identifier of the user who requested password reset',
    example: '1ab0c8f0-7d3a-4f5f-80ab-e3f98cd5ef70',
    format: 'uuid',
  })
  userId: string;

  @ApiProperty({
    description:
      'Short-lived reset token. Use it with /auth/reset-password to set a new password.',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  resetToken: string;
}
