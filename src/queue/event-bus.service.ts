import { Injectable, Logger } from '@nestjs/common';
import { JobsOptions, QueueEvents, Worker } from 'bullmq';
import { QueueService } from './queue.service';

type EventHandler<T = unknown> = (payload: T) => Promise<void> | void;

@Injectable()
export class EventBusService {
  private readonly logger = new Logger(EventBusService.name);
  private readonly queueName = 'domain-events';
  private readonly handlers = new Map<string, EventHandler>();
  private worker?: Worker;
  private queueEvents?: QueueEvents;

  constructor(private readonly queueService: QueueService) {}

  async emit<T = unknown>(
    eventName: string,
    payload: T,
    options?: JobsOptions,
  ): Promise<void> {
    const queue = this.queueService.getQueue(this.queueName);
    await queue.add(eventName, payload, options);
    this.logger.debug(`Event '${eventName}' queued`);
  }

  async subscribe<T = unknown>(
    eventName: string,
    handler: EventHandler<T>,
  ): Promise<void> {
    if (this.handlers.has(eventName)) {
      this.logger.warn(`Overwriting handler for event '${eventName}'`);
    }

    this.handlers.set(eventName, handler as EventHandler);
    await this.ensureWorker();
    this.logger.log(`Handler registered for event '${eventName}'`);
  }

  unsubscribe(eventName: string): void {
    this.handlers.delete(eventName);
    this.logger.log(`Handler removed for event '${eventName}'`);
  }

  private async ensureWorker(): Promise<void> {
    if (this.worker) {
      return;
    }

    this.worker = this.queueService.createWorker(
      this.queueName,
      async (job) => {
        const handler = this.handlers.get(job.name);

        if (!handler) {
          this.logger.warn(`No handler registered for event '${job.name}'`);
          return;
        }

        await handler(job.data);
      },
      {
        concurrency: 10,
      },
    );

    await this.registerQueueEvents();
  }

  private async registerQueueEvents(): Promise<void> {
    if (this.queueEvents) {
      return;
    }

    this.queueEvents = await this.queueService.getQueueEvents(this.queueName);

    this.queueEvents.on('completed', ({ jobId }) => {
      this.logger.debug(`Event job '${jobId as string}' completed`);
    });

    this.queueEvents.on('failed', ({ jobId, failedReason }) => {
      this.logger.error(
        `Event job '${jobId as string}' failed: ${failedReason}`,
      );
    });
  }
}
