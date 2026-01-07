import type { ConfigService } from '@nestjs/config';
import type { SetPasswordAudience } from 'src/common/email/email.types';

function normalizeBaseUrl(appUrl: string): string {
  return appUrl.endsWith('/') ? appUrl.slice(0, -1) : appUrl;
}

function normalizePath(path: string): string {
  if (!path) return '/auth/password-set';
  return path.startsWith('/') ? path : `/${path}`;
}

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value.trim());
}

function toEnvKeyFragment(value: string): string {
  return value
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

export function buildPasswordSetLink({
  configService,
  token,
  audience,
  roleName,
}: {
  configService: Pick<ConfigService, 'get'>;
  token: string;
  audience: SetPasswordAudience;
  roleName?: string;
}): string {
  const defaultAppUrl = configService.get<string>(
    'APP_URL',
    'http://localhost:3000',
  );
  const defaultPasswordSetPath = configService.get<string>(
    'PASSWORD_SET_PATH',
    '/auth/password-set',
  );

  const roleKey = roleName ? toEnvKeyFragment(roleName) : '';
  const roleAppUrlKey = roleKey ? `ROLE_${roleKey}_APP_URL` : undefined;
  const rolePasswordSetPathKey = roleKey
    ? `ROLE_${roleKey}_PASSWORD_SET_PATH`
    : undefined;

  const appUrlKey =
    audience === 'customer'
      ? 'CUSTOMER_APP_URL'
      : audience === 'admin'
        ? 'ADMIN_APP_URL'
        : undefined;

  const passwordSetPathKey =
    audience === 'customer'
      ? 'CUSTOMER_PASSWORD_SET_PATH'
      : audience === 'admin'
        ? 'ADMIN_PASSWORD_SET_PATH'
        : undefined;

  const roleOverrideAppUrl = roleAppUrlKey
    ? configService.get<string>(roleAppUrlKey)
    : undefined;
  const roleOverridePasswordSetPath = rolePasswordSetPathKey
    ? configService.get<string>(rolePasswordSetPathKey)
    : undefined;

  const audienceOverrideAppUrl = appUrlKey
    ? configService.get<string>(appUrlKey)
    : undefined;
  const audienceOverridePasswordSetPath = passwordSetPathKey
    ? configService.get<string>(passwordSetPathKey)
    : undefined;

  const appUrlCandidate =
    (roleOverrideAppUrl && roleOverrideAppUrl.trim().length > 0
      ? roleOverrideAppUrl
      : undefined) ??
    (audienceOverrideAppUrl && audienceOverrideAppUrl.trim().length > 0
      ? audienceOverrideAppUrl
      : undefined) ??
    defaultAppUrl;

  const appUrl = isHttpUrl(appUrlCandidate) ? appUrlCandidate : defaultAppUrl;

  const passwordSetPath =
    (roleOverridePasswordSetPath &&
    roleOverridePasswordSetPath.trim().length > 0
      ? roleOverridePasswordSetPath
      : undefined) ??
    (audienceOverridePasswordSetPath &&
    audienceOverridePasswordSetPath.trim().length > 0
      ? audienceOverridePasswordSetPath
      : undefined) ??
    defaultPasswordSetPath;

  const base = normalizeBaseUrl(appUrl);
  const path = normalizePath(passwordSetPath);

  return `${base}${path}?token=${encodeURIComponent(token)}`;
}
