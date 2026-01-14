import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as crypto from 'crypto';
import { AppCacheService } from 'src/common/cache/app-cache.service';

type OAuthExchangePayload = {
  userId: string;
  createdAt: number;
};

@Injectable()
export class OAuthExchangeService {
  private readonly prefix = 'auth:oauth:exchange:';
  private readonly ttlSeconds = 60;

  constructor(private readonly cache: AppCacheService) {}

  private makeKey(exchangeCode: string) {
    return `${this.prefix}${exchangeCode}`;
  }

  issue(userId: string): Promise<string> {
    const exchangeCode = crypto.randomBytes(32).toString('base64url');
    const payload: OAuthExchangePayload = {
      userId,
      createdAt: Date.now(),
    };

    return this.cache
      .set(this.makeKey(exchangeCode), payload, this.ttlSeconds)
      .then(() => exchangeCode);
  }

  async consume(exchangeCode: string): Promise<OAuthExchangePayload> {
    if (!exchangeCode || exchangeCode.trim().length < 16) {
      throw new UnauthorizedException('Invalid exchange code');
    }

    const key = this.makeKey(exchangeCode);
    const payload = await this.cache.get<OAuthExchangePayload>(key);
    if (!payload?.userId) {
      throw new UnauthorizedException('Exchange code expired or already used');
    }

    await this.cache.del(key);
    return payload;
  }
}
