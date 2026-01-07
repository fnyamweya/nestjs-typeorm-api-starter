import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsUUID } from 'class-validator';

export class PublicListCategoriesDto {
  @ApiPropertyOptional({
    description: 'Optional taxonomy id to scope the results',
  })
  @IsOptional()
  @IsUUID('4')
  taxonomyId?: string;

  @ApiPropertyOptional({
    description: 'Preferred locale for translated fields',
    example: 'en',
  })
  @IsOptional()
  @IsString()
  locale?: string;
}
