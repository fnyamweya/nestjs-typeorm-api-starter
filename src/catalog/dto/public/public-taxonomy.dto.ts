import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class PublicTaxonomyDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  code: string;

  @ApiProperty()
  name: string;

  @ApiPropertyOptional()
  description?: string;

  @ApiPropertyOptional({ required: false, nullable: true, example: 'mdi:tag-outline' })
  icon?: string | null;

  @ApiPropertyOptional({ required: false, nullable: true, example: 'https://cdn.example.com/taxonomy/avatar.png' })
  avatarUrl?: string | null;

  @ApiProperty()
  isDefault: boolean;
}
