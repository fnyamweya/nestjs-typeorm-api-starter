import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  OneToMany,
  Index,
  JoinColumn,
} from 'typeorm';
import { Taxonomy } from './taxonomy.entity';
import { CategoryTranslation } from './category-translation.entity';
import { CategoryClosure } from './category-closure.entity';
import { CategoryChannelSettings } from './category-channel-settings.entity';
import { CategoryAttribute } from './category-attribute.entity';
import { ProductCategory } from './product-category.entity';

@Entity('category')
@Index('idx_category_taxonomy_sort', ['taxonomyId', 'sortOrder'])
@Index('idx_category_taxonomy_active', ['taxonomyId', 'isActive'])
@Index('uq_category_key_per_taxonomy', ['taxonomyId', 'key'], { unique: true })
@Index('uq_category_slug_per_taxonomy', ['taxonomyId', 'slug'], { unique: true })
export class Category {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'taxonomy_id', type: 'uuid' })
  taxonomyId: string;

  @ManyToOne(() => Taxonomy, (taxonomy) => taxonomy.categories, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'taxonomy_id' })
  taxonomy: Taxonomy;

  @Column({ name: 'parent_id', type: 'uuid', nullable: true })
  parentId?: string;

  @ManyToOne(() => Category, (category) => category.children, {
    onDelete: 'SET NULL',
  })
  @JoinColumn({ name: 'parent_id' })
  parent?: Category;

  @Column({ type: 'text', nullable: false })
  key: string;

  @Column({ type: 'text', nullable: false })
  slug: string;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

  @Column({ name: 'is_leaf', type: 'boolean', default: false })
  isLeaf: boolean;

  @Column({ name: 'sort_order', type: 'int', default: 0 })
  sortOrder: number;

  @Column({ type: 'text', nullable: true })
  icon?: string;

  @Column({ name: 'image_url', type: 'text', nullable: true })
  imageUrl?: string;

  @Column({ name: 'meta_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  metaJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(() => CategoryTranslation, (translation) => translation.category)
  translations: CategoryTranslation[];

  @OneToMany(() => Category, (category) => category.parent)
  children: Category[];

  @OneToMany(() => CategoryClosure, (closure) => closure.ancestor)
  ancestorClosures: CategoryClosure[];

  @OneToMany(() => CategoryClosure, (closure) => closure.descendant)
  descendantClosures: CategoryClosure[];

  @OneToMany(
    () => CategoryChannelSettings,
    (categoryChannel) => categoryChannel.category,
  )
  channelSettings: CategoryChannelSettings[];

  @OneToMany(
    () => CategoryAttribute,
    (categoryAttribute) => categoryAttribute.category,
  )
  categoryAttributes: CategoryAttribute[];

  @OneToMany(() => ProductCategory, (productCategory) => productCategory.category)
  productCategories: ProductCategory[];
}
