import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsOptional, IsUUID } from 'class-validator';

export class AttachZoneShippingMethodDto {
  @ApiPropertyOptional({
    description: 'Existing global shipping method id to attach to this zone',
  })
  @IsUUID()
  shippingMethodId: string;

  @ApiPropertyOptional({ description: 'Override active flag for this zone' })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}
