import { ApiProperty } from '@nestjs/swagger';
import { IsString, MaxLength } from 'class-validator';

export class UpdateGoogleOAuthSecretDto {
  @ApiProperty({ description: 'Google OAuth client secret.' })
  @IsString()
  @MaxLength(2048)
  clientSecret: string;
}
// Legacy: Use Google OAuth profiles instead
