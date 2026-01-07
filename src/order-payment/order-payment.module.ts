import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Order } from '../order/entities/order.entity';
import { OrderItem } from '../order/entities/order-item.entity';
import { OrderPayment } from './entities/order-payment.entity';
import { PaymentAllocation } from './entities/payment-allocation.entity';
import { OrderPaymentService } from './order-payment.service';
import { OrderPaymentController } from './order-payment.controller';
import { AccountingModule } from '../accounting/accounting.module';

@Module({
  imports: [
    AccountingModule,
    TypeOrmModule.forFeature([
      Order,
      OrderItem,
      OrderPayment,
      PaymentAllocation,
    ]),
  ],
  providers: [OrderPaymentService],
  controllers: [OrderPaymentController],
  exports: [OrderPaymentService, TypeOrmModule],
})
export class OrderPaymentModule {}
