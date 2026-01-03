import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis, { RedisOptions } from 'ioredis';

@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  private client?: Redis;
  private ready = false;

  constructor(private readonly configService: ConfigService) {}

  getClient(): Redis {
    if (!this.client) {
      const options = this.buildOptions();
      const client = new Redis(options);

      client.on('ready', () => {
        this.ready = true;
        this.logger.log('Redis connection ready');
      });

      client.on('end', () => {
        this.ready = false;
        this.logger.warn('Redis connection ended');
      });

      client.on('error', (err) => {
        this.ready = false;
        this.logger.warn(`Redis error: ${err?.message ?? 'unknown error'}`);
      });

      this.client = client;
    }

    return this.client;
  }

  isReady(): boolean {
    return this.ready;
  }

  buildOptions(): RedisOptions {
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

    if (password) options.password = password;
    if (username) options.username = username;
    if (tlsEnabled) options.tls = {};

    return options;
  }

  async onModuleDestroy() {
    if (this.client) {
      try {
        await this.client.quit();
      } catch {
        // ignore
      }
    }
  }
}
