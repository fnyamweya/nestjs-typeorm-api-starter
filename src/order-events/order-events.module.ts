import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Order } from '../order/entities/order.entity';
import { OrderEvent } from './entities/order-event.entity';
import { OrderEventsService } from './order-events.service';
import { OrderEventsController } from './order-events.controller';

@Module({
  imports: [TypeOrmModule.forFeature([Order, OrderEvent])],
  providers: [OrderEventsService],
  controllers: [OrderEventsController],
  exports: [OrderEventsService],
})
export class OrderEventsModule {}
