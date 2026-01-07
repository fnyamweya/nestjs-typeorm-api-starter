import { PartialType } from '@nestjs/swagger';
import { CreateCustomerTierRuleDto } from './create-customer-tier-rule.dto';

export class UpdateCustomerTierRuleDto extends PartialType(
  CreateCustomerTierRuleDto,
) {}
