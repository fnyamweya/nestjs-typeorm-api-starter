import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PaymentMethod } from './entities/payment-method.entity';
import { PaymentMethodService } from './services/payment-method.service';
import { PaymentMethodController } from './controllers/payment-method.controller';
import { PaymentMethodSeeder } from './seeders/payment-method.seeder';
import { PaymentProvider } from 'src/payment-provider/entities/payment-provider.entity';

@Module({
  imports: [TypeOrmModule.forFeature([PaymentMethod, PaymentProvider])],
  providers: [PaymentMethodService, PaymentMethodSeeder],
  controllers: [PaymentMethodController],
  exports: [TypeOrmModule, PaymentMethodService, PaymentMethodSeeder],
})
export class PaymentMethodModule {}
