import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { ActivityLogModule } from './activity-log/activity-log.module';
import { ActivityLogInterceptor } from './activity-log/interceptors/activity-log.interceptor';
import { SettingModule } from './setting/setting.module';
import { CommonModule } from './common/common.module';
import dataSource from './data-source';
import { QueueModule } from './queue/queue.module';
import { CatalogModule } from './catalog/catalog.module';
import { OrderModule } from './order/order.module';
import { PromotionModule } from './promotion/promotion.module';
import { FeatureFlagModule } from './feature-flag/feature-flag.module';
import { MpesaModule } from './mpesa/mpesa.module';
import { SmsModule } from './sms/sms.module';
import { AddressModule } from './address/address.module';
import { CustomerAddressModule } from './customer-address/customer-address.module';
import { CustomerShippingAddressModule } from './customer-shipping-address/customer-shipping-address.module';
import { LocationModule } from './location/location.module';
import { WhatsappModule } from './whatsapp/whatsapp.module';
import { ChannelsModule } from './channels/channels.module';
import { CustomerTierModule } from './customer-tier/customer-tier.module';
import { BannerModule } from './banner/banner.module';
import { PricingModule } from './pricing/pricing.module';
import { CurrencyModule } from './currency/currency.module';
import { CheckoutModule } from './checkout/checkout.module';
import { PaymentProviderModule } from './payment-provider/payment-provider.module';
import { PaymentMethodModule } from './payment-method/payment-method.module';
import { OrderPaymentModule } from './order-payment/order-payment.module';
import { OrderFulfillmentModule } from './order-fulfillment/order-fulfillment.module';
import { OrderEventsModule } from './order-events/order-events.module';
import { AccountingModule } from './accounting/accounting.module';

@Module({
  imports: [
    CommonModule,
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRoot({
      ...dataSource.options,
      autoLoadEntities: true,
    }),
    AuthModule,
    UserModule,
    ActivityLogModule,
    SettingModule,
    QueueModule,
    CatalogModule,
    OrderModule,
    PromotionModule,
    FeatureFlagModule,
    MpesaModule,
    SmsModule,
    WhatsappModule,
    AddressModule,
    CustomerAddressModule,
    CustomerShippingAddressModule,
    LocationModule,
    ChannelsModule,
    CustomerTierModule,
    BannerModule,
    PricingModule,
    CurrencyModule,
    CheckoutModule,
    PaymentProviderModule,
    PaymentMethodModule,
    OrderPaymentModule,
    AccountingModule,
    OrderFulfillmentModule,
    OrderEventsModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_INTERCEPTOR,
      useClass: ActivityLogInterceptor,
    },
  ],
})
export class AppModule {}
