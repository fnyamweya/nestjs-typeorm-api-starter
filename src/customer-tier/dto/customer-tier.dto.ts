import { ApiProperty } from '@nestjs/swagger';

export class CustomerTierDto {
  @ApiProperty()
  id: string;

  @ApiProperty({ example: 'BASE' })
  code: string;

  @ApiProperty({ example: 'Base' })
  name: string;

  @ApiProperty({ example: 0 })
  priority: number;

  @ApiProperty({ example: true })
  isActive: boolean;

  @ApiProperty({ type: Object })
  configJson: Record<string, unknown>;

  @ApiProperty({ type: Object })
  metadata: Record<string, unknown>;

  @ApiProperty()
  createdAt: string;

  @ApiProperty()
  updatedAt: string;
}
