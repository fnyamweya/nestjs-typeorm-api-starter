import { Entity, PrimaryColumn, Column, ManyToOne, JoinColumn, Index } from 'typeorm';
import { Product } from './product.entity';
import { AttributeDefinition } from './attribute-definition.entity';

@Entity('product_attribute_value')
@Index('idx_product_attr_string', ['attributeId', 'valueString'])
@Index('idx_product_attr_number', ['attributeId', 'valueNumber'])
export class ProductAttributeValue {
  @PrimaryColumn({ name: 'product_id', type: 'uuid' })
  productId: string;

  @PrimaryColumn({ name: 'attribute_id', type: 'uuid' })
  attributeId: string;

  @ManyToOne(() => Product, (product) => product.attributeValues, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'product_id' })
  product: Product;

  @ManyToOne(() => AttributeDefinition, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'attribute_id' })
  attribute: AttributeDefinition;

  @Column({ name: 'value_string', type: 'text', nullable: true })
  valueString?: string;

  @Column({ name: 'value_number', type: 'numeric', nullable: true })
  valueNumber?: string;

  @Column({ name: 'value_boolean', type: 'boolean', nullable: true })
  valueBoolean?: boolean;

  @Column({ name: 'value_json', type: 'jsonb', nullable: true })
  valueJson?: Record<string, unknown>;
}
