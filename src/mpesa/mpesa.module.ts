import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MpesaController } from './controllers/mpesa.controller';
import { MpesaService } from './services/mpesa.service';
import { MpesaTransaction } from './entities/mpesa-transaction.entity';
import { Order } from 'src/order/entities/order.entity';
import { QueueModule } from 'src/queue/queue.module';

@Module({
  imports: [QueueModule, TypeOrmModule.forFeature([MpesaTransaction, Order])],
  controllers: [MpesaController],
  providers: [MpesaService],
  exports: [MpesaService],
})
export class MpesaModule {}
