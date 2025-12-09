import { IsBoolean, IsOptional, IsString } from 'class-validator';

export class UploadFileDto {
  @IsOptional()
  @IsString()
  folder?: string;

  @IsOptional()
  @IsString()
  filenameOverride?: string;

  @IsOptional()
  @IsBoolean()
  generateSignedUrl?: boolean;
}
