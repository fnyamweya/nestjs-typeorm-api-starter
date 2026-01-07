import { ApiProperty } from '@nestjs/swagger';

export class S3ResponseDto {
  @ApiProperty({
    description: 'S3 endpoint URL (may be empty when using AWS defaults)',
    example: 'https://s3.amazonaws.com',
  })
  s3Endpoint: string;

  @ApiProperty({
    description:
      'Optional public base URL used to construct permanent file URLs (custom domain / Worker / CDN).',
    example: 'https://media.example.com',
    nullable: true,
  })
  s3PublicBaseUrl?: string;

  @ApiProperty({
    description:
      'Optional Cloudflare R2 Public Development URL base (r2.dev). Prefer this for public URL construction when set.',
    example: 'https://pub-xxxxxxxxxxxxxxxx.r2.dev',
    nullable: true,
  })
  s3PublicDevBaseUrl?: string;

  @ApiProperty({ description: 'S3 region', example: 'us-east-1' })
  s3Region: string;

  @ApiProperty({ description: 'Bucket name', example: 'my-app-bucket' })
  bucketName: string;

  @ApiProperty({
    description: 'Whether path-style addressing is enabled',
    example: true,
  })
  forcePathStyle: boolean;

  @ApiProperty({
    description: 'Flag indicating if S3 is enabled',
    example: true,
  })
  s3Enabled: boolean;

  @ApiProperty({
    description: 'Whether an access key id is configured (stored encrypted)',
    example: true,
  })
  hasAccessKeyId: boolean;

  @ApiProperty({
    description: 'Whether a secret access key is configured (stored encrypted)',
    example: true,
  })
  hasSecretAccessKey: boolean;

  @ApiProperty({
    description: 'Creation timestamp',
    example: new Date().toISOString(),
  })
  createdAt?: Date;

  @ApiProperty({
    description: 'Update timestamp',
    example: new Date().toISOString(),
  })
  updatedAt?: Date;
}
