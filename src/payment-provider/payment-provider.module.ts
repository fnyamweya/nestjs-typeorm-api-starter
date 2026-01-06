import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PaymentProvider } from './entities/payment-provider.entity';
import { PaymentProviderService } from './services/payment-provider.service';
import { PaymentProviderController } from './controllers/payment-provider.controller';
import { PaymentProviderSeeder } from './seeders/payment-provider.seeder';

@Module({
  imports: [TypeOrmModule.forFeature([PaymentProvider])],
  providers: [PaymentProviderService, PaymentProviderSeeder],
  controllers: [PaymentProviderController],
  exports: [TypeOrmModule, PaymentProviderService, PaymentProviderSeeder],
})
export class PaymentProviderModule {}
