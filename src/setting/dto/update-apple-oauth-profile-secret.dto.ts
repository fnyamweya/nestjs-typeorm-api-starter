import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class UpdateAppleOAuthProfileSecretDto {
  @ApiProperty({
    description:
      'Apple private key string (p8). Stored encrypted at rest; never returned.',
    example: '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----',
  })
  @IsString()
  @IsNotEmpty()
  privateKey: string;
}
