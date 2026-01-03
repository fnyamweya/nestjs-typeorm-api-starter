import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class PublicBrandDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty()
  slug: string;

  @ApiPropertyOptional()
  description?: string;

  @ApiPropertyOptional()
  logoUrl?: string;

  @ApiPropertyOptional()
  websiteUrl?: string;
}
