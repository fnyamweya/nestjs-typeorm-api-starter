import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  OneToMany,
  Index,
} from 'typeorm';
import { Product } from './product.entity';
import { ProductOptionValue } from './product-option-value.entity';

@Entity('product_option')
@Index('uq_product_option_name', ['productId', 'name'], { unique: true })
export class ProductOption {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'product_id', type: 'uuid' })
  productId: string;

  @ManyToOne(() => Product, (product) => product.options, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'product_id' })
  product: Product;

  @Column({ type: 'text', nullable: false })
  name: string;

  @Column({ type: 'int', default: 0 })
  position: number;

  @OneToMany(() => ProductOptionValue, (optionValue) => optionValue.option)
  values: ProductOptionValue[];
}
