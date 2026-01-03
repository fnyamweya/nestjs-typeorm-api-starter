import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class UpdateWhatsappSecretsDto {
  @ApiPropertyOptional({
    description:
      'Meta app secret used to verify webhook signatures (X-Hub-Signature-256). Stored encrypted at rest.',
    example: '0123456789abcdef0123456789abcdef',
  })
  @IsOptional()
  @IsString()
  appSecret?: string;

  @ApiPropertyOptional({
    description:
      'Meta webhook verify token used during the GET verification handshake. Stored encrypted at rest.',
    example: 'my_verify_token',
  })
  @IsOptional()
  @IsString()
  webhookVerifyToken?: string;
}
