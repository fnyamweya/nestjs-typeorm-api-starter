import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Setting } from '../setting/entities/setting.entity';
import { SmsServiceUtils } from '../common/utils/sms-service.utils';
import { QueueModule } from '../queue/queue.module';
import { OrderSmsService } from './services/order-sms.service';
import { OrderSmsListener } from './order-sms.listener';
import { Order } from '../order/entities/order.entity';
import { User } from '../user/entities/user.entity';

@Module({
  imports: [QueueModule, TypeOrmModule.forFeature([Setting, Order, User])],
  providers: [SmsServiceUtils, OrderSmsService, OrderSmsListener],
  exports: [SmsServiceUtils, OrderSmsService],
})
export class SmsModule {}
