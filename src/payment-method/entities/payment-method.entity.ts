import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { PaymentProvider } from 'src/payment-provider/entities/payment-provider.entity';
import { PaymentMethodChannel } from './payment-method-channel.entity';
import { PaymentMethodCountryConfig } from './payment-method-country-config.entity';
import { PaymentMethodCurrency } from './payment-method-currency.entity';

@Entity('payment_method')
export class PaymentMethod {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index({ unique: true })
  @Column({ type: 'text' })
  code: string;

  @Index()
  @Column({ name: 'provider_id', type: 'uuid' })
  providerId: string;

  @ManyToOne(() => PaymentProvider, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'provider_id' })
  provider?: PaymentProvider;

  @Column({ type: 'text' })
  name: string;

  @Column({ type: 'text', nullable: true })
  description?: string;

  @Index()
  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

  @OneToMany(() => PaymentMethodChannel, (link) => link.paymentMethod)
  channelLinks?: PaymentMethodChannel[];

  @OneToMany(() => PaymentMethodCountryConfig, (link) => link.paymentMethod)
  countryLinks?: PaymentMethodCountryConfig[];

  @OneToMany(() => PaymentMethodCurrency, (link) => link.paymentMethod)
  currencyLinks?: PaymentMethodCurrency[];

  @Column({ name: 'config_json', type: 'jsonb', default: () => "'{}'::jsonb" })
  configJson: Record<string, unknown>;

  @Column({ type: 'jsonb', default: () => "'{}'::jsonb" })
  metadata: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
