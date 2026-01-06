import { ApiProperty } from '@nestjs/swagger';
import { ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { UpsertAddressDto } from '../../address/dto/upsert-address.dto';

export class SetCheckoutDeliveryDto {
  @ApiProperty({ type: UpsertAddressDto })
  @ValidateNested()
  @Type(() => UpsertAddressDto)
  shippingAddress: UpsertAddressDto;
}
