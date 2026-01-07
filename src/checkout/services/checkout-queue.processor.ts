import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { QueueService } from 'src/queue/queue.service';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { CheckoutSession } from '../entities/checkout-session.entity';

const CHECKOUT_QUEUE = 'checkout';
const EXPIRE_JOB = 'expire-session';

@Injectable()
export class CheckoutQueueProcessor implements OnModuleInit {
  private readonly logger = new Logger(CheckoutQueueProcessor.name);

  constructor(
    private readonly queueService: QueueService,
    private readonly cache: AppCacheService,
    @InjectRepository(CheckoutSession)
    private readonly checkoutSessionRepo: Repository<CheckoutSession>,
  ) {}

  private key(sessionId: string) {
    return `checkout:session:${sessionId}`;
  }

  onModuleInit() {
    if (process.env.NODE_ENV === 'test') {
      // Avoid long-lived BullMQ workers during Jest runs.
      return;
    }

    this.queueService.createWorker(
      CHECKOUT_QUEUE,
      async (job) => {
        if (job.name !== EXPIRE_JOB) return;

        const sessionId = String(job.data?.sessionId);
        if (!sessionId) return;

        const row = await this.checkoutSessionRepo.findOne({
          where: { id: sessionId },
        });
        if (!row) {
          await this.cache.del(this.key(sessionId));
          return;
        }

        if (row.status !== 'active') {
          await this.cache.del(this.key(sessionId));
          return;
        }

        if (row.expiresAt.getTime() > Date.now()) {
          // Session was extended/recreated; do nothing.
          return;
        }

        row.status = 'expired';
        await this.checkoutSessionRepo.save(row);
        await this.cache.del(this.key(sessionId));

        this.logger.debug(`Checkout session expired: ${sessionId}`);
      },
      { concurrency: 5 },
    );
  }
}
