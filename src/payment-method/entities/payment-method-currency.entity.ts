import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryColumn,
} from 'typeorm';
import { PaymentMethod } from './payment-method.entity';
import { Currency } from '../../catalog/entities/currency.entity';

@Entity('payment_method_currency')
@Index('idx_payment_method_currency_active', ['paymentMethodId', 'isActive'])
export class PaymentMethodCurrency {
  @PrimaryColumn({ name: 'payment_method_id', type: 'uuid' })
  paymentMethodId: string;

  @PrimaryColumn({ name: 'currency_code', type: 'char', length: 3 })
  currencyCode: string;

  @ManyToOne(() => PaymentMethod, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'payment_method_id' })
  paymentMethod: PaymentMethod;

  @ManyToOne(() => Currency, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'currency_code', referencedColumnName: 'code' })
  currency: Currency;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;
}
