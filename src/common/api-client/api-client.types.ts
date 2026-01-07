import type { AxiosRequestConfig, AxiosResponse, Method } from 'axios';

export type ApiClientRetryPolicy = {
  attempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
};

export type ApiClientRequest<TResponse = unknown> = {
  method: Method;

  /**
   * Either provide a full URL, or provide `baseUrl` + `path`.
   */
  url?: string;
  baseUrl?: string;
  path?: string;

  headers?: Record<string, string | undefined>;
  params?: Record<string, unknown>;
  data?: unknown;

  timeoutMs?: number;
  retry?: Partial<ApiClientRetryPolicy>;

  /**
   * Optional hint for logging/metrics.
   */
  operation?: string;

  /**
   * Extra Axios options when needed.
   */
  axios?: Omit<
    AxiosRequestConfig,
    'url' | 'baseURL' | 'method' | 'headers' | 'params' | 'data' | 'timeout'
  >;
};

export type ApiClientResponse<TResponse = unknown> = {
  data: TResponse;
  status: number;
  headers: Record<string, unknown>;
  raw: AxiosResponse<TResponse>;
};
