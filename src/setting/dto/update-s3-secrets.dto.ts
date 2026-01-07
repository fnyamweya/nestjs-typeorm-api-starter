import { IsOptional, IsString, MaxLength } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateS3SecretsDto {
  @ApiPropertyOptional({
    description:
      'Access key ID for S3 credentials. Stored encrypted at rest and never returned by the API.',
    example: 'AKIA...REDACTED',
    maxLength: 512,
  })
  @IsOptional()
  @IsString({ message: 'S3 access key id must be a string' })
  @MaxLength(512, {
    message: 'S3 access key id must not exceed 512 characters',
  })
  accessKeyId?: string;

  @ApiPropertyOptional({
    description:
      'Secret access key for S3 credentials. Stored encrypted at rest and never returned by the API.',
    example: 'super-secret',
    maxLength: 1024,
  })
  @IsOptional()
  @IsString({ message: 'S3 secret access key must be a string' })
  @MaxLength(1024, {
    message: 'S3 secret access key must not exceed 1024 characters',
  })
  secretAccessKey?: string;
}
