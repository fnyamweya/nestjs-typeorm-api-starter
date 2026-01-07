import { ApiProperty } from '@nestjs/swagger';

export class WhatsappSecretsResponseDto {
  @ApiProperty({
    description:
      'Whether a WhatsApp app secret is configured (value is never returned).',
    example: true,
  })
  hasAppSecret: boolean;

  @ApiProperty({
    description:
      'Whether a WhatsApp webhook verify token is configured (value is never returned).',
    example: true,
  })
  hasWebhookVerifyToken: boolean;

  @ApiProperty({ required: false, type: Date })
  updatedAt?: Date;
}
