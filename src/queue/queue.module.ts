import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { QueueService } from './queue.service';
import { EventBusService } from './event-bus.service';

@Global()
@Module({
  imports: [ConfigModule],
  providers: [QueueService, EventBusService],
  exports: [QueueService, EventBusService],
})
export class QueueModule {}
