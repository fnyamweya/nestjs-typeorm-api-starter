import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Order } from '../order/entities/order.entity';
import { OrderItem } from '../order/entities/order-item.entity';
import { OrderShippingAddress } from '../order/entities/order-shipping-address.entity';
import { ShippingMethod } from '../shipping/entities/shipping-method.entity';
import { OrderFulfillment } from './entities/order-fulfillment.entity';
import { FulfillmentPackage } from './entities/fulfillment-package.entity';
import { FulfillmentItem } from './entities/fulfillment-item.entity';
import { PackageItem } from './entities/package-item.entity';
import { OrderFulfillmentService } from './order-fulfillment.service';
import { OrderFulfillmentController } from './order-fulfillment.controller';
import { OrderEventsModule } from '../order-events/order-events.module';
import { AccountingModule } from '../accounting/accounting.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      Order,
      OrderItem,
      OrderShippingAddress,
      ShippingMethod,
      OrderFulfillment,
      FulfillmentPackage,
      FulfillmentItem,
      PackageItem,
    ]),
    OrderEventsModule,
    AccountingModule,
  ],
  providers: [OrderFulfillmentService],
  controllers: [OrderFulfillmentController],
  exports: [OrderFulfillmentService, TypeOrmModule],
})
export class OrderFulfillmentModule {}
