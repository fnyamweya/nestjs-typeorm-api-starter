import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CatalogModule } from '../catalog/catalog.module';
import { Order } from './entities/order.entity';
import { OrderItem } from './entities/order-item.entity';
import { OrderLevelCharge } from './entities/order-level-charge.entity';
import { OrderItemCharge } from './entities/order-item-charge.entity';
import { OrderService } from './services/order.service';
import { OrderController } from './controllers/order.controller';

@Module({
  imports: [
    TypeOrmModule.forFeature([Order, OrderItem, OrderLevelCharge, OrderItemCharge]),
    CatalogModule,
  ],
  controllers: [OrderController],
  providers: [OrderService],
  exports: [TypeOrmModule, OrderService],
})
export class OrderModule {}
