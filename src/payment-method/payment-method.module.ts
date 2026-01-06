import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PaymentMethod } from './entities/payment-method.entity';
import { PaymentMethodService } from './services/payment-method.service';
import { PaymentMethodController } from './controllers/payment-method.controller';
import { PaymentMethodSeeder } from './seeders/payment-method.seeder';
import { PaymentProvider } from 'src/payment-provider/entities/payment-provider.entity';
import { Channel } from 'src/channels/entities/channel.entity';
import { PaymentMethodChannel } from './entities/payment-method-channel.entity';
import { CountryConfig } from 'src/country/entities/country-config.entity';
import { PaymentMethodCountryConfig } from './entities/payment-method-country-config.entity';
import { Currency } from 'src/catalog/entities/currency.entity';
import { PaymentMethodCurrency } from './entities/payment-method-currency.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      PaymentMethod,
      PaymentProvider,
      PaymentMethodChannel,
      PaymentMethodCountryConfig,
      PaymentMethodCurrency,
      Channel,
      CountryConfig,
      Currency,
    ]),
  ],
  providers: [PaymentMethodService, PaymentMethodSeeder],
  controllers: [PaymentMethodController],
  exports: [TypeOrmModule, PaymentMethodService, PaymentMethodSeeder],
})
export class PaymentMethodModule {}
