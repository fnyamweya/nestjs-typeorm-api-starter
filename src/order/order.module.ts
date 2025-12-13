import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Order } from './entities/order.entity';
import { OrderItem } from './entities/order-item.entity';
import { OrderLevelCharge } from './entities/order-level-charge.entity';
import { OrderItemCharge } from './entities/order-item-charge.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([Order, OrderItem, OrderLevelCharge, OrderItemCharge]),
  ],
  exports: [TypeOrmModule],
})
export class OrderModule {}
