import type { ConfigService } from '@nestjs/config';

function normalizeBaseUrl(appUrl: string): string {
  return appUrl.endsWith('/') ? appUrl.slice(0, -1) : appUrl;
}

function normalizePath(path: string): string {
  if (!path) return '/';
  return path.startsWith('/') ? path : `/${path}`;
}

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value.trim());
}

function safeReturnToPath({
  returnTo,
  baseUrl,
}: {
  returnTo?: string;
  baseUrl: string;
}): string | undefined {
  if (!returnTo) return undefined;

  const trimmed = returnTo.trim();
  if (!trimmed) return undefined;

  // Allow a relative path directly.
  if (trimmed.startsWith('/')) {
    return trimmed;
  }

  // If it's an absolute URL, only allow it if the origin matches the baseUrl.
  if (isHttpUrl(trimmed)) {
    try {
      const base = new URL(baseUrl);
      const candidate = new URL(trimmed);
      if (candidate.origin === base.origin) {
        return `${candidate.pathname}${candidate.search}${candidate.hash}`;
      }
    } catch {
      return undefined;
    }
  }

  return undefined;
}

export function buildAdminOAuthRedirectUrl({
  configService,
  returnTo,
}: {
  configService: Pick<ConfigService, 'get'>;
  returnTo?: string;
}): string {
  const appUrl =
    configService.get<string>('ADMIN_APP_URL') ||
    configService.get<string>('APP_URL') ||
    'http://localhost:3000';

  const baseUrl = isHttpUrl(appUrl) ? appUrl : 'http://localhost:3000';

  const defaultSuccessPath = configService.get<string>(
    'ADMIN_OAUTH_SUCCESS_PATH',
    '/dashboard',
  );

  const chosenPath =
    safeReturnToPath({ returnTo, baseUrl }) || normalizePath(defaultSuccessPath);

  return `${normalizeBaseUrl(baseUrl)}${chosenPath}`;
}
