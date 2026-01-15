import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class PublicCategoryDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  taxonomyId: string;

  @ApiPropertyOptional()
  parentId?: string;

  @ApiProperty()
  key: string;

  @ApiProperty()
  slug: string;

  @ApiProperty()
  name: string;

  @ApiPropertyOptional()
  description?: string;

  @ApiPropertyOptional()
  icon?: string;

  @ApiPropertyOptional()
  avatarUrl?: string;

  @ApiPropertyOptional()
  imageUrl?: string;

  @ApiProperty()
  sortOrder: number;

  @ApiProperty()
  isLeaf: boolean;
}
