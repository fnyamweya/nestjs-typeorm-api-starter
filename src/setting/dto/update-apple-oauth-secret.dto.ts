import { ApiProperty } from '@nestjs/swagger';
import { IsString, MaxLength } from 'class-validator';

export class UpdateAppleOAuthSecretDto {
  @ApiProperty({
    description:
      'Apple private key contents. Can include newlines. Will be stored encrypted at rest.',
  })
  @IsString()
  @MaxLength(20000)
  privateKey: string;
}
