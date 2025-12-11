import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Category } from './category.entity';
import { AttributeDefinition } from './attribute-definition.entity';

@Entity('category_attribute')
@Index('uq_category_attribute', ['categoryId', 'attributeId'], { unique: true })
@Index('idx_category_attribute_cat', ['categoryId', 'isFilterable'])
export class CategoryAttribute {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'category_id', type: 'uuid' })
  categoryId: string;

  @ManyToOne(() => Category, (category) => category.categoryAttributes, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'category_id' })
  category: Category;

  @Column({ name: 'attribute_id', type: 'uuid' })
  attributeId: string;

  @ManyToOne(
    () => AttributeDefinition,
    (attributeDefinition) => attributeDefinition.id,
    {
      onDelete: 'CASCADE',
    },
  )
  @JoinColumn({ name: 'attribute_id' })
  attribute: AttributeDefinition;

  @Column({ name: 'is_required', type: 'boolean', default: false })
  isRequired: boolean;

  @Column({ name: 'is_filterable', type: 'boolean', default: false })
  isFilterable: boolean;

  @Column({ name: 'filter_type', type: 'text', nullable: true })
  filterType?: string;

  @Column({ name: 'sort_order', type: 'int', default: 0 })
  sortOrder: number;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;
}
