import { IsBoolean, IsOptional, IsString } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UploadFileDto {
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
}
