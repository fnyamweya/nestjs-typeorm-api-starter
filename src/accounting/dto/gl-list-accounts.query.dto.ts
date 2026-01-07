import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsBooleanString, IsOptional } from 'class-validator';

export class GlListAccountsQueryDto {
  @ApiPropertyOptional({
    description: 'Include inactive accounts (default false)',
    example: 'false',
  })
  @IsOptional()
  @IsBooleanString()
  includeInactive?: string;
}
