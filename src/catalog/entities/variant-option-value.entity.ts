import { Entity, PrimaryColumn, Column, ManyToOne, JoinColumn, Index } from 'typeorm';
import { ProductVariant } from './product-variant.entity';
import { ProductOption } from './product-option.entity';
import { ProductOptionValue } from './product-option-value.entity';

@Entity('variant_option_value')
@Index('idx_variant_option_value', ['variantId'])
export class VariantOptionValue {
  @PrimaryColumn({ name: 'variant_id', type: 'uuid' })
  variantId: string;

  @PrimaryColumn({ name: 'option_id', type: 'uuid' })
  optionId: string;

  @PrimaryColumn({ name: 'option_value_id', type: 'uuid' })
  optionValueId: string;

  @ManyToOne(() => ProductVariant, (variant) => variant.optionValues, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'variant_id' })
  variant: ProductVariant;

  @ManyToOne(() => ProductOption, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'option_id' })
  option: ProductOption;

  @ManyToOne(() => ProductOptionValue, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'option_value_id' })
  optionValue: ProductOptionValue;
}
