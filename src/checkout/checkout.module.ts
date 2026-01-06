import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CheckoutController } from './controllers/checkout.controller';
import { CheckoutService } from './services/checkout.service';
import { CheckoutSession } from './entities/checkout-session.entity';
import { AppCacheModule } from 'src/common/cache/app-cache.module';
import { ShippingModule } from 'src/shipping/shipping.module';
import { CustomerShippingAddressModule } from 'src/customer-shipping-address/customer-shipping-address.module';
import { OrderModule } from 'src/order/order.module';
import { CheckoutQueueProcessor } from './services/checkout-queue.processor';

@Module({
  imports: [
    TypeOrmModule.forFeature([CheckoutSession]),
    AppCacheModule,
    ShippingModule,
    CustomerShippingAddressModule,
    OrderModule,
  ],
  controllers: [CheckoutController],
  providers: [CheckoutService, CheckoutQueueProcessor],
  exports: [CheckoutService],
})
export class CheckoutModule {}
