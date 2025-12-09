import { Module, Global } from '@nestjs/common';
import { ResponseInterceptor } from './interceptors/response.interceptor';
import { HttpExceptionFilter } from './filters/http-exception.filter';
import { S3ClientUtils } from './utils/s3-client.utils';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Setting } from 'src/setting/entities/setting.entity';
import { EmailServiceUtils } from './utils/email-service.utils';
import { CommonUploadController } from './controllers/common-upload.controller';

@Global()
@Module({
  imports: [TypeOrmModule.forFeature([Setting])],
  providers: [
    ResponseInterceptor,
    HttpExceptionFilter,
    S3ClientUtils,
    EmailServiceUtils,
  ],
  controllers: [CommonUploadController],
  exports: [
    ResponseInterceptor,
    HttpExceptionFilter,
    S3ClientUtils,
    EmailServiceUtils,
  ],
})
export class CommonModule {}
