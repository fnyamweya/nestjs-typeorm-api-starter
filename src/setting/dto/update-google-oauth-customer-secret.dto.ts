import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class UpdateGoogleOAuthCustomerSecretDto {
  @ApiProperty({
    description:
      'Google OAuth client secret for the CUSTOMER app (stored encrypted at rest)',
    example: 'GOCSPX-xxxxx',
  })
  @IsString()
  @IsNotEmpty()
  clientSecret: string;
}
// Legacy: Use Google OAuth profiles instead
