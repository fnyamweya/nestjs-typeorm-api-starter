import { PartialType } from '@nestjs/swagger';
import { CreateCustomerTierDto } from './create-customer-tier.dto';

export class UpdateCustomerTierDto extends PartialType(CreateCustomerTierDto) {}
