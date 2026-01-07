import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryColumn,
} from 'typeorm';
import { PaymentMethod } from './payment-method.entity';
import { CountryConfig } from '../../country/entities/country-config.entity';

@Entity('payment_method_country_config')
@Index('idx_payment_method_country_config_active', [
  'paymentMethodId',
  'isActive',
])
export class PaymentMethodCountryConfig {
  @PrimaryColumn({ name: 'payment_method_id', type: 'uuid' })
  paymentMethodId: string;

  @PrimaryColumn({ name: 'country_config_id', type: 'uuid' })
  countryConfigId: string;

  @ManyToOne(() => PaymentMethod, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'payment_method_id' })
  paymentMethod: PaymentMethod;

  @ManyToOne(() => CountryConfig, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'country_config_id' })
  countryConfig: CountryConfig;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;
}
