import { Transform } from 'class-transformer';
import { IsOptional, IsString, IsBoolean } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { PaginationFilterDto } from 'src/common/dto/pagination-filter.dto';

export class FilterUserDto extends PaginationFilterDto {
  @ApiPropertyOptional({
    description: 'Text search applied to user name, email, or phone',
    example: 'jane',
  })
  @IsOptional()
  @IsString({ message: 'Search must be a string' })
  search?: string;

  @ApiPropertyOptional({
    description: 'Filter to only banned or unbanned users',
    example: false,
  })
  @IsOptional()
  @IsBoolean({ message: 'Is banned must be a boolean' })
  @Transform(({ value }) => {
    if (value === undefined || value === null) return undefined;
    if (value === 'true' || value === '1' || value === true) return true;
    if (value === 'false' || value === '0' || value === false) return false;
    return undefined;
  })
  isBanned?: boolean;
}
