import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsInt, IsOptional, IsString, Max, Min } from 'class-validator';

export class PresignObjectDto {
  @ApiProperty({
    description: 'Full object key in storage (e.g. products/<uuid>-image.png)',
    example: 'products/75bcec47-2fe9-435f-be50-0ea1461a1a40-obraz.png',
  })
  @IsString()
  objectKey: string;

  @ApiPropertyOptional({
    description:
      'Signed URL expiry in seconds (min 60, max 86400). Default 3600.',
    example: 3600,
  })
  @IsOptional()
  @IsInt()
  @Min(60)
  @Max(86400)
  expiresIn?: number;
}
