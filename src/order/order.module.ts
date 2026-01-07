import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CatalogModule } from '../catalog/catalog.module';
import { PromotionModule } from '../promotion/promotion.module';
import { SettingModule } from '../setting/setting.module';
import { TaxService } from './services/tax.service';
import { Order } from './entities/order.entity';
import { ShippingModule } from '../shipping/shipping.module';
import { OrderItem } from './entities/order-item.entity';
import { OrderLevelCharge } from './entities/order-level-charge.entity';
import { OrderItemCharge } from './entities/order-item-charge.entity';
import { OrderShippingAddress } from './entities/order-shipping-address.entity';
import { OrderService } from './services/order.service';
import { OrderController } from './controllers/order.controller';
import { User } from '../user/entities/user.entity';
import { Location } from '../location/entities/location.entity';
import { CurrencyModule } from '../currency/currency.module';
import { CustomerShippingAddressModule } from '../customer-shipping-address/customer-shipping-address.module';
import { OrderPaymentModule } from '../order-payment/order-payment.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      Order,
      OrderItem,
      OrderLevelCharge,
      OrderItemCharge,
      OrderShippingAddress,
      User,
      Location,
    ]),
    CatalogModule,
    PromotionModule,
    // need settings for shipping & tax
    SettingModule,
    // Shipping module provides the shipping matrix
    ShippingModule,
    CurrencyModule,
    CustomerShippingAddressModule,
    OrderPaymentModule,
  ],
  controllers: [OrderController],
  providers: [OrderService, TaxService],
  exports: [TypeOrmModule, OrderService],
})
export class OrderModule {}
