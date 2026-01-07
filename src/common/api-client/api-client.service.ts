import {
  BadGatewayException,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios, {
  type AxiosError,
  type AxiosInstance,
  isAxiosError,
} from 'axios';
import {
  type ApiClientRequest,
  type ApiClientResponse,
  type ApiClientRetryPolicy,
} from './api-client.types';
import { RequestContextService } from '../request-context/request-context.service';

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_RETRY: ApiClientRetryPolicy = {
  attempts: 2,
  baseDelayMs: 150,
  maxDelayMs: 2_000,
};

const SENSITIVE_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'x-api-key',
  'api-key',
  'x-auth-token',
  'cookie',
  'set-cookie',
]);

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function jitter(ms: number): number {
  // full jitter
  return Math.floor(Math.random() * ms);
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function redactHeaders(
  headers?: Record<string, string | undefined>,
): Record<string, string | undefined> {
  if (!headers) return {};
  const out: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key] = SENSITIVE_HEADERS.has(key.toLowerCase()) ? '[REDACTED]' : value;
  }
  return out;
}

@Injectable()
export class ApiClientService {
  private readonly logger = new Logger(ApiClientService.name);
  private readonly client: AxiosInstance;

  constructor(
    private readonly configService: ConfigService,
    private readonly requestContext: RequestContextService,
  ) {
    const timeoutMs = Number(
      this.configService.get<string>('HTTP_TIMEOUT_MS') ?? DEFAULT_TIMEOUT_MS,
    );

    this.client = axios.create({
      timeout: Number.isFinite(timeoutMs) ? timeoutMs : DEFAULT_TIMEOUT_MS,
      // We keep validateStatus default so Axios throws on non-2xx.
    });
  }

  async request<TResponse = unknown>(
    input: ApiClientRequest<TResponse>,
  ): Promise<ApiClientResponse<TResponse>> {
    const url = input.url ?? this.buildUrl(input.baseUrl, input.path);
    if (!url) {
      throw new BadGatewayException(
        'ApiClientService: missing url/baseUrl+path',
      );
    }

    const requestId = this.requestContext.requestId;

    const mergedHeaders: Record<string, string | undefined> = {
      ...(input.headers ?? {}),
      ...(requestId ? { 'x-request-id': requestId } : {}),
    };

    const retry: ApiClientRetryPolicy = {
      ...DEFAULT_RETRY,
      ...(input.retry ?? {}),
    };

    const timeout =
      typeof input.timeoutMs === 'number' && Number.isFinite(input.timeoutMs)
        ? input.timeoutMs
        : undefined;

    const startedAt = Date.now();
    let lastError: unknown;

    for (let attempt = 1; attempt <= Math.max(1, retry.attempts); attempt++) {
      const attemptStarted = Date.now();

      try {
        const res = await this.client.request<TResponse>({
          url,
          method: input.method,
          headers: mergedHeaders,
          params: input.params,
          data: input.data,
          timeout,
          ...(input.axios ?? {}),
        });

        const durationMs = Date.now() - attemptStarted;
        this.logger.debug({
          msg: 'Outbound request succeeded',
          operation: input.operation,
          method: input.method,
          url,
          status: res.status,
          durationMs,
          attempt,
        });

        return {
          data: res.data,
          status: res.status,
          headers: (res.headers ?? {}) as Record<string, unknown>,
          raw: res,
        };
      } catch (err: unknown) {
        lastError = err;

        const durationMs = Date.now() - attemptStarted;

        const axiosErr = isAxiosError(err) ? (err as AxiosError) : undefined;
        const status = axiosErr?.response?.status;

        this.logger.warn({
          msg: 'Outbound request failed',
          operation: input.operation,
          method: input.method,
          url,
          status,
          durationMs,
          attempt,
          headers: redactHeaders(mergedHeaders),
        });

        if (
          attempt >= Math.max(1, retry.attempts) ||
          !this.shouldRetry(input.method, axiosErr)
        ) {
          break;
        }

        const delay = this.computeDelayMs(retry, attempt);
        await sleep(delay);
      }
    }

    // Standardize the thrown exception so upstream services can rely on it.
    if (isAxiosError(lastError)) {
      const status = lastError.response?.status;

      // If upstream is explicitly rate-limiting or temporarily unavailable.
      if (status === 429 || status === 503) {
        throw new ServiceUnavailableException('Upstream service unavailable');
      }

      throw new BadGatewayException('Upstream request failed');
    }

    throw new BadGatewayException(
      `Upstream request failed after ${Date.now() - startedAt}ms`,
    );
  }

  private buildUrl(baseUrl?: string, path?: string): string | undefined {
    if (!baseUrl && !path) return undefined;
    if (!baseUrl) return path;
    if (!path) return baseUrl;

    const base = baseUrl.replace(/\/$/, '');
    const p = path.startsWith('/') ? path : `/${path}`;
    return `${base}${p}`;
  }

  private shouldRetry(method: string | undefined, error?: AxiosError): boolean {
    const m = (method ?? '').toUpperCase();
    const idempotent =
      m === 'GET' ||
      m === 'HEAD' ||
      m === 'PUT' ||
      m === 'DELETE' ||
      m === 'OPTIONS';
    if (!idempotent) return false;

    if (!error) return false;

    // Network/timeout errors: retry
    if (!error.response) return true;

    const status = error.response.status;
    return status >= 500 || status === 429;
  }

  private computeDelayMs(
    policy: ApiClientRetryPolicy,
    attempt: number,
  ): number {
    const exp = policy.baseDelayMs * Math.pow(2, Math.max(0, attempt - 1));
    const capped = clamp(exp, 0, policy.maxDelayMs);
    return jitter(capped);
  }
}
