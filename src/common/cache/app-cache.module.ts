import { Global, Module } from '@nestjs/common';
import { RedisModule } from '../redis/redis.module';
import { AppCacheService } from './app-cache.service';
import { ShippingCatalogContextCacheIndexService } from './shipping-catalog-context-cache-index.service';

@Global()
@Module({
  imports: [RedisModule],
  providers: [AppCacheService, ShippingCatalogContextCacheIndexService],
  exports: [AppCacheService, ShippingCatalogContextCacheIndexService],
})
export class AppCacheModule {}
