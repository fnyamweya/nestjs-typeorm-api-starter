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

  @ApiProperty()
  isDefault: boolean;
}
