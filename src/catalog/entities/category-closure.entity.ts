import { Entity, PrimaryColumn, Column, ManyToOne, JoinColumn, Index } from 'typeorm';
import { Category } from './category.entity';

@Entity('category_closure')
@Index('idx_cat_closure_ancestor', ['ancestorId', 'depth'])
@Index('idx_cat_closure_descendant', ['descendantId', 'depth'])
export class CategoryClosure {
  @PrimaryColumn({ name: 'ancestor_id', type: 'uuid' })
  ancestorId: string;

  @PrimaryColumn({ name: 'descendant_id', type: 'uuid' })
  descendantId: string;

  @ManyToOne(() => Category, (category) => category.ancestorClosures, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'ancestor_id' })
  ancestor: Category;

  @ManyToOne(() => Category, (category) => category.descendantClosures, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'descendant_id' })
  descendant: Category;

  @Column({ type: 'int', nullable: false })
  depth: number;
}
