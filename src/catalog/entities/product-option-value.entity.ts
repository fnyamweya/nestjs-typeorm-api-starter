import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { ProductOption } from './product-option.entity';

@Entity('product_option_value')
@Index('uq_option_value', ['optionId', 'value'], { unique: true })
export class ProductOptionValue {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'option_id', type: 'uuid' })
  optionId: string;

  @ManyToOne(() => ProductOption, (option) => option.values, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'option_id' })
  option: ProductOption;

  @Column({ type: 'text', nullable: false })
  value: string;

  @Column({ type: 'int', default: 0 })
  position: number;
}
