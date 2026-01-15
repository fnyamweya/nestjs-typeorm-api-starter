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
  
  @ApiPropertyOptional({ required: false, nullable: true, example: 'mdi:tag' })
  icon?: string | null;
  
  @ApiPropertyOptional({ required: false, nullable: true, example: 'https://cdn.example.com/brand/avatar.png' })
  avatarUrl?: string | null;

  @ApiPropertyOptional()
  websiteUrl?: string;
}
