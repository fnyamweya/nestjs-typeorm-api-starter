import { ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';

export class GlListJournalEntriesQueryDto {
  @ApiPropertyOptional({ example: 1, description: 'Page number (default 1)' })
  @IsOptional()
  @IsInt()
  @Min(1)
  page?: number;

  @ApiPropertyOptional({ example: 50, description: 'Page size (default 50, max 200)' })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(200)
  limit?: number;

  @ApiPropertyOptional({
    example: '2026-01-01T00:00:00Z',
    description: 'Filter by postedAt >= from (ISO timestamp)',
  })
  @IsOptional()
  @IsString()
  from?: string;

  @ApiPropertyOptional({
    example: '2026-01-31T23:59:59Z',
    description: 'Filter by postedAt <= to (ISO timestamp)',
  })
  @IsOptional()
  @IsString()
  to?: string;

  @ApiPropertyOptional({ example: 'ORDER_PAYMENT' })
  @IsOptional()
  @IsString()
  sourceType?: string;

  @ApiPropertyOptional({ example: '0f3b0e2a-2e7d-4f78-9b6c-7d7f6f6f6f6f' })
  @IsOptional()
  @IsString()
  sourceId?: string;

  @ApiPropertyOptional({ example: 'order_payment:0f3b0e2a-2e7d-4f78-9b6c-7d7f6f6f6f6f' })
  @IsOptional()
  @IsString()
  idempotencyKey?: string;

  @ApiPropertyOptional({ example: '4000:SALES_REVENUE', description: 'Filter entries touching this account code' })
  @IsOptional()
  @IsString()
  accountCode?: string;

  @ApiPropertyOptional({ example: 'day', enum: ['day', 'month'] })
  @IsOptional()
  @IsIn(['day', 'month'])
  bucket?: 'day' | 'month';
}
