import { Global, Module } from '@nestjs/common';
import { ApiClientService } from './api-client.service';
import { RequestContextService } from '../request-context/request-context.service';

@Global()
@Module({
  providers: [RequestContextService, ApiClientService],
  exports: [RequestContextService, ApiClientService],
})
export class ApiClientModule {}
