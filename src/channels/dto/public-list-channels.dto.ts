import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, MaxLength } from 'class-validator';

export class PublicListChannelsDto {
  @ApiPropertyOptional({
    description: 'Case-insensitive search on code or name.',
  })
  @IsOptional()
  @IsString()
  @MaxLength(120)
  q?: string;
}
