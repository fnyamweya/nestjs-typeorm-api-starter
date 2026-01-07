import {
  IsBoolean,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUrl,
  MaxLength,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateS3SettingDto {
  @ApiPropertyOptional({
    description:
      'S3 endpoint URL (required for MinIO/other S3-compatible storage). Leave empty to use AWS defaults.',
    example: 'https://s3.amazonaws.com',
    maxLength: 2048,
  })
  @IsOptional()
  @IsString({ message: 'S3 endpoint must be a string' })
  @MaxLength(2048, { message: 'S3 endpoint must not exceed 2048 characters' })
  @IsUrl(
    { require_protocol: true },
    { message: 'S3 endpoint must be a valid URL (include http/https)' },
  )
  s3Endpoint?: string;

  @ApiPropertyOptional({
    description:
      'Optional public base URL used to build permanent file URLs (e.g. custom domain pointing to R2/Worker). Example: https://media.example.com',
    example: 'https://media.example.com',
    maxLength: 2048,
  })
  @IsOptional()
  @IsString({ message: 'S3 public base URL must be a string' })
  @MaxLength(2048, {
    message: 'S3 public base URL must not exceed 2048 characters',
  })
  @IsUrl(
    { require_protocol: true },
    { message: 'S3 public base URL must be a valid URL (include http/https)' },
  )
  s3PublicBaseUrl?: string;

  @ApiPropertyOptional({
    description:
      'Optional Cloudflare R2 Public Development URL base (r2.dev) for the bucket. If provided, public uploads will return URLs using this base. Example: https://pub-xxxxxxxxxxxxxxxx.r2.dev',
    example: 'https://pub-xxxxxxxxxxxxxxxx.r2.dev',
    maxLength: 2048,
  })
  @IsOptional()
  @IsString({ message: 'S3 public dev base URL must be a string' })
  @MaxLength(2048, {
    message: 'S3 public dev base URL must not exceed 2048 characters',
  })
  @IsUrl(
    { require_protocol: true },
    {
      message:
        'S3 public dev base URL must be a valid URL (include http/https)',
    },
  )
  s3PublicDevBaseUrl?: string;

  @ApiProperty({
    description: 'AWS region (or any region value for S3-compatible providers)',
    example: 'us-east-1',
    maxLength: 255,
  })
  @IsString({ message: 'S3 region must be a string' })
  @IsNotEmpty({ message: 'S3 region is required' })
  @MaxLength(255, { message: 'S3 region must not exceed 255 characters' })
  s3Region: string;

  @ApiProperty({
    description: 'Target bucket name used for uploads and downloads',
    example: 'my-app-bucket',
    maxLength: 255,
  })
  @IsString({ message: 'S3 bucket name must be a string' })
  @IsNotEmpty({ message: 'S3 bucket name is required' })
  @MaxLength(255, { message: 'S3 bucket name must not exceed 255 characters' })
  bucketName: string;

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

  @ApiPropertyOptional({
    description:
      'Whether to force path-style addressing (recommended for MinIO and some S3-compatible providers)',
    example: true,
  })
  @IsOptional()
  @IsBoolean({ message: 'S3 force path style must be a boolean value' })
  @Transform(({ value }) => value === 'true' || value === true)
  forcePathStyle?: boolean;

  @ApiPropertyOptional({
    description: 'Flag indicating if object storage is enabled',
    example: true,
  })
  @IsOptional()
  @IsBoolean({ message: 'S3 enabled must be a boolean value' })
  @Transform(({ value }) => value === 'true' || value === true)
  s3Enabled?: boolean;
}
