import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CustomerTierRuleDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  tierId: string;

  @ApiProperty({ example: 'BASE' })
  tierCode: string;

  @ApiProperty({ example: true })
  isActive: boolean;

  @ApiProperty({ example: 0 })
  priority: number;

  @ApiPropertyOptional()
  validFrom?: string;

  @ApiPropertyOptional()
  validUntil?: string;

  @ApiProperty({ type: Object })
  rule: Record<string, unknown>;

  @ApiPropertyOptional()
  description?: string;

  @ApiProperty()
  createdAt: string;

  @ApiProperty()
  updatedAt: string;
}
