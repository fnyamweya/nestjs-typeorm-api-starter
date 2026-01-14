import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class UpdateGoogleOAuthProfileSecretDto {
  @ApiProperty({
    description: 'Google OAuth client secret (stored encrypted at rest)',
    example: 'GOCSPX-xxxxxxxxxxxxxxxxxxxx',
  })
  @IsString()
  @IsNotEmpty()
  clientSecret: string;
}
