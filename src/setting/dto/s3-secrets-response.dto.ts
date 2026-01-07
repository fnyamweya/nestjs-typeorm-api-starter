import { ApiProperty } from '@nestjs/swagger';

export class S3SecretsResponseDto {
  @ApiProperty({
    description: 'Whether an access key id is stored',
    example: true,
  })
  hasAccessKeyId: boolean;

  @ApiProperty({
    description: 'Whether a secret access key is stored',
    example: true,
  })
  hasSecretAccessKey: boolean;

  @ApiProperty({
    description: 'Last update timestamp for either secret',
    example: new Date().toISOString(),
  })
  updatedAt?: Date;
}
