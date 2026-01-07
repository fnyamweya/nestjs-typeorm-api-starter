import { PartialType } from '@nestjs/swagger';
import { CreateProductContextOverrideDto } from './create-product-context-override.dto';

export class UpdateProductContextOverrideDto extends PartialType(
  CreateProductContextOverrideDto,
) {}
