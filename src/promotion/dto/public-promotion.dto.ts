import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class PublicPromotionDto {
  @ApiProperty({
    description: 'Promotion id',
    example: '3a3d0e5e-5b69-4c1f-8df3-7a6d7c2c0b11',
  })
  id: string;

  @ApiProperty({
    description: 'Promotion code (also used as coupon code where applicable)',
    example: 'WELCOME10',
  })
  code: string;

  @ApiPropertyOptional({
    description: 'Marketing name',
    example: 'Welcome discount',
  })
  name?: string;

  @ApiPropertyOptional({
    description: 'Marketing description',
    example: '10% off your first order',
  })
  description?: string;

  @ApiPropertyOptional({
    description: 'ISO date-time when the promo becomes valid',
    example: '2026-01-01T00:00:00.000Z',
  })
  validFrom?: string;

  @ApiPropertyOptional({
    description: 'ISO date-time when the promo expires',
    example: '2026-12-31T23:59:59.999Z',
  })
  validTo?: string;
}
