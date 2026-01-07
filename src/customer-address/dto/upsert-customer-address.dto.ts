import { ApiProperty } from '@nestjs/swagger';
import { IsIn, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { UpsertAddressDto } from '../../address/dto/upsert-address.dto';
import {
  CUSTOMER_ADDRESS_TYPES,
  CustomerAddressType,
} from '../customer-address.types';

export class UpsertCustomerAddressDto {
  @ApiProperty({ enum: CUSTOMER_ADDRESS_TYPES, description: 'Address type' })
  @IsIn(CUSTOMER_ADDRESS_TYPES)
  type: CustomerAddressType;

  @ApiProperty({ type: UpsertAddressDto })
  @ValidateNested()
  @Type(() => UpsertAddressDto)
  address: UpsertAddressDto;
}
