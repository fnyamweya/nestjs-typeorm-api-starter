import { Module, Global } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { ResponseInterceptor } from './interceptors/response.interceptor';
import { HttpExceptionFilter } from './filters/http-exception.filter';
import { S3ClientUtils } from './utils/s3-client.utils';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Setting } from 'src/setting/entities/setting.entity';
import { EmailServiceUtils } from './utils/email-service.utils';
import { SettingCryptoService } from './utils/setting-crypto.service';
import { CommonUploadController } from './controllers/common-upload.controller';
import { ApiClientModule } from './api-client/api-client.module';
import { RequestContextInterceptor } from './request-context/request-context.interceptor';
import { RedisModule } from './redis/redis.module';
import { AppCacheModule } from './cache/app-cache.module';
import { S3ConfigService } from './s3/s3-config.service';
import { UploadWorkerService } from './uploads/upload-worker.service';
import { RateLimitService } from './security/rate-limit.service';

@Global()
@Module({
  imports: [
    TypeOrmModule.forFeature([Setting]),
    ApiClientModule,
    RedisModule,
    AppCacheModule,
  ],
  providers: [
    ResponseInterceptor,
    HttpExceptionFilter,
    {
      provide: APP_INTERCEPTOR,
      useClass: RequestContextInterceptor,
    },
    S3ConfigService,
    S3ClientUtils,
    UploadWorkerService,
    RateLimitService,
    EmailServiceUtils,
    SettingCryptoService,
  ],
  controllers: [CommonUploadController],
  exports: [
    ResponseInterceptor,
    HttpExceptionFilter,
    ApiClientModule,
    RedisModule,
    AppCacheModule,
    S3ConfigService,
    S3ClientUtils,
    EmailServiceUtils,
    SettingCryptoService,
    RateLimitService,
  ],
})
export class CommonModule {}
