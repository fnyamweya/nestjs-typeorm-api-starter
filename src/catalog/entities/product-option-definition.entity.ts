import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Product } from './product.entity';

@Entity('product_option_definition')
@Index('uq_product_option_definition', ['productId', 'code'], { unique: true })
export class ProductOptionDefinition {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'product_id', type: 'uuid' })
  productId: string;

  @ManyToOne(() => Product, (product) => product.optionDefinitions, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'product_id' })
  product: Product;

  @Column({ type: 'text' })
  code: string;

  @Column({ type: 'text' })
  label: string;

  @Column({ name: 'allowed_values', type: 'text', array: true, nullable: true })
  allowedValues?: string[];

  @Column({ name: 'is_required', type: 'boolean', default: false })
  required: boolean;

  @Column({ type: 'int', default: 0 })
  position: number;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
