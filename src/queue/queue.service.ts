import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  JobsOptions,
  Processor,
  Queue,
  QueueEvents,
  QueueEventsOptions,
  QueueOptions,
  Worker,
  WorkerOptions,
} from 'bullmq';
import { RedisOptions } from 'ioredis';

@Injectable()
export class QueueService implements OnModuleDestroy {
  private readonly logger = new Logger(QueueService.name);
  private readonly queues = new Map<string, Queue>();
  private readonly queueEvents = new Map<string, QueueEvents>();
  private readonly workers = new Set<Worker>();
  private readonly redisOptions: RedisOptions;

  constructor(private readonly configService: ConfigService) {
    this.redisOptions = this.buildConnectionOptions();
  }

  private buildConnectionOptions(): RedisOptions {
    const host = this.configService.get<string>('REDIS_HOST', '127.0.0.1');
    const port = Number(this.configService.get<string>('REDIS_PORT', '6379'));
    const password = this.configService.get<string>('REDIS_PASSWORD');
    const username = this.configService.get<string>('REDIS_USERNAME');
    const db = Number(this.configService.get<string>('REDIS_DB', '0'));
    const tlsEnabled =
      this.configService.get<string>('REDIS_TLS', 'false') === 'true';

    const options: RedisOptions = {
      host,
      port,
      db,
      maxRetriesPerRequest: null,
    };

    if (password) {
      options.password = password;
    }

    if (username) {
      options.username = username;
    }

    if (tlsEnabled) {
      options.tls = {};
    }

    return options;
  }

  getQueue(name: string, options: QueueOptions = {}): Queue {
    if (!this.queues.has(name)) {
      const queue = new Queue(name, {
        connection: this.redisOptions,
        defaultJobOptions: {
          removeOnComplete: true,
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 1000,
          },
        },
        ...options,
      });

      this.queues.set(name, queue);
      this.logger.log(`Queue '${name}' initialized`);
    }

    return this.queues.get(name)!;
  }

  async addJob<T = unknown>(
    queueName: string,
    jobName: string,
    data: T,
    options?: JobsOptions,
  ) {
    const queue = this.getQueue(queueName);
    return queue.add(jobName, data, options);
  }

  createWorker<T = any, R = any>(
    name: string,
    processor: Processor<T, R>,
    options: WorkerOptions = {},
  ): Worker<T, R> {
    const worker = new Worker<T, R>(name, processor, {
      connection: this.redisOptions,
      concurrency: 5,
      ...options,
    });

    worker.on('error', (error) => {
      this.logger.error(
        `Worker error in queue '${name}': ${error.message}`,
        error.stack,
      );
    });

    this.workers.add(worker);
    return worker;
  }

  async getQueueEvents(
    name: string,
    options: QueueEventsOptions = {},
  ): Promise<QueueEvents> {
    if (!this.queueEvents.has(name)) {
      const events = new QueueEvents(name, {
        connection: this.redisOptions,
        ...options,
      });

      await events.waitUntilReady();
      this.queueEvents.set(name, events);
      this.logger.log(`Queue events registered for '${name}'`);
    }

    return this.queueEvents.get(name)!;
  }

  async onModuleDestroy() {
    for (const worker of this.workers) {
      await worker.close();
    }

    for (const events of this.queueEvents.values()) {
      await events.close();
    }

    for (const queue of this.queues.values()) {
      await queue.close();
    }
  }
}
