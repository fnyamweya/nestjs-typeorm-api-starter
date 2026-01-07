import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { v4 as uuidv4 } from 'uuid';
import { RequestContextService } from './request-context.service';

const REQUEST_ID_HEADER = 'x-request-id';

@Injectable()
export class RequestContextInterceptor implements NestInterceptor {
  constructor(private readonly requestContext: RequestContextService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const http = context.switchToHttp();
    const req = http.getRequest<
      Request & { headers?: Record<string, unknown> }
    >();
    const res = http.getResponse<{
      setHeader?: (name: string, value: string) => void;
    }>();

    const headerValue = (req?.headers?.[REQUEST_ID_HEADER] ??
      req?.headers?.[REQUEST_ID_HEADER.toUpperCase()]) as
      | string
      | string[]
      | undefined;

    const requestId =
      (Array.isArray(headerValue) ? headerValue[0] : headerValue) || uuidv4();

    if (typeof res?.setHeader === 'function') {
      res.setHeader(REQUEST_ID_HEADER, requestId);
    }

    return this.requestContext.run({ requestId }, () => next.handle());
  }
}
