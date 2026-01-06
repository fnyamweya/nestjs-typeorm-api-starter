import { IsBoolean, IsIn, IsOptional, IsString } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export const UPLOAD_FILE_TYPES = [
  'image',
  'document',
  'video',
  'audio',
  'avatar',
  'other',
] as const;

export type UploadFileType = (typeof UPLOAD_FILE_TYPES)[number];

export class UploadFileDto {
  @ApiPropertyOptional({
    description:
      'Optional file category used to determine the target directory. If provided, it takes precedence over `folder`.',
    example: 'image',
    enum: UPLOAD_FILE_TYPES,
  })
  @IsOptional()
  @IsString()
  @IsIn(UPLOAD_FILE_TYPES as unknown as string[], {
    message: `filetype must be one of: ${UPLOAD_FILE_TYPES.join(', ')}`,
  })
  filetype?: UploadFileType;

  @ApiPropertyOptional({
    description: 'Target folder within the storage bucket',
    example: 'avatars',
  })
  @IsOptional()
  @IsString()
  folder?: string;

  @ApiPropertyOptional({
    description: 'Override for the generated file name',
    example: 'profile-picture.png',
  })
  @IsOptional()
  @IsString()
  filenameOverride?: string;

  @ApiPropertyOptional({
    description: 'Generate a temporary signed URL for the uploaded file',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  generateSignedUrl?: boolean;

  @ApiPropertyOptional({
    description:
      'Whether the uploaded file should be treated as publicly accessible (return publicUrl when configured). If false, the API will return a signed url for access.',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  isPublic?: boolean;
}
