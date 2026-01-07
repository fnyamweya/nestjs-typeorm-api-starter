export type ThemeMode = 'system' | 'light' | 'dark';
export type NewsletterFrequency = 'daily' | 'weekly' | 'monthly' | 'never';

export interface NotificationChannelPreferences {
  enabled: boolean;
  orderUpdates: boolean;
  promotions: boolean;
  securityAlerts: boolean;
}

export interface UserProfilePreferences {
  notifications: {
    sms: NotificationChannelPreferences;
    email: NotificationChannelPreferences & {
      newsletters: boolean;
    };
  };
  newsletters: {
    enabled: boolean;
    frequency: NewsletterFrequency;
  };
  theme: {
    mode: ThemeMode;
  };
  locale: {
    language: string;
    currency: string;
    timezone?: string;
  };
  ui: {
    reduceMotion: boolean;
    highContrast: boolean;
  };
  privacy: {
    showEmail: boolean;
    showPhone: boolean;
    showProfileImage: boolean;
  };
}

export const DEFAULT_PROFILE_PREFERENCES: UserProfilePreferences = {
  notifications: {
    sms: {
      enabled: false,
      orderUpdates: true,
      promotions: false,
      securityAlerts: true,
    },
    email: {
      enabled: true,
      orderUpdates: true,
      promotions: false,
      securityAlerts: true,
      newsletters: true,
    },
  },
  newsletters: {
    enabled: true,
    frequency: 'weekly',
  },
  theme: {
    mode: 'system',
  },
  locale: {
    language: 'en',
    currency: 'USD',
  },
  ui: {
    reduceMotion: false,
    highContrast: false,
  },
  privacy: {
    showEmail: false,
    showPhone: false,
    showProfileImage: true,
  },
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function asString(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.trim().length > 0
    ? value
    : fallback;
}

function asThemeMode(value: unknown, fallback: ThemeMode): ThemeMode {
  return value === 'system' || value === 'light' || value === 'dark'
    ? value
    : fallback;
}

function asNewsletterFrequency(
  value: unknown,
  fallback: NewsletterFrequency,
): NewsletterFrequency {
  return value === 'daily' ||
    value === 'weekly' ||
    value === 'monthly' ||
    value === 'never'
    ? value
    : fallback;
}

export function normalizeProfilePreferences(
  input: unknown,
): UserProfilePreferences {
  const base = DEFAULT_PROFILE_PREFERENCES;
  if (!isPlainObject(input))
    return {
      ...base,
      notifications: {
        ...base.notifications,
        sms: { ...base.notifications.sms },
        email: { ...base.notifications.email },
      },
    };

  const notifications = isPlainObject(input.notifications)
    ? input.notifications
    : {};

  const sms = isPlainObject((notifications as any).sms)
    ? (notifications as any).sms
    : {};
  const email = isPlainObject((notifications as any).email)
    ? (notifications as any).email
    : {};

  const newsletters = isPlainObject(input.newsletters) ? input.newsletters : {};
  const theme = isPlainObject(input.theme) ? input.theme : {};
  const locale = isPlainObject(input.locale) ? input.locale : {};
  const ui = isPlainObject(input.ui) ? input.ui : {};
  const privacy = isPlainObject(input.privacy) ? input.privacy : {};

  return {
    notifications: {
      sms: {
        enabled: asBoolean(sms.enabled, base.notifications.sms.enabled),
        orderUpdates: asBoolean(
          sms.orderUpdates,
          base.notifications.sms.orderUpdates,
        ),
        promotions: asBoolean(
          sms.promotions,
          base.notifications.sms.promotions,
        ),
        securityAlerts: asBoolean(
          sms.securityAlerts,
          base.notifications.sms.securityAlerts,
        ),
      },
      email: {
        enabled: asBoolean(email.enabled, base.notifications.email.enabled),
        orderUpdates: asBoolean(
          email.orderUpdates,
          base.notifications.email.orderUpdates,
        ),
        promotions: asBoolean(
          email.promotions,
          base.notifications.email.promotions,
        ),
        securityAlerts: asBoolean(
          email.securityAlerts,
          base.notifications.email.securityAlerts,
        ),
        newsletters: asBoolean(
          email.newsletters,
          base.notifications.email.newsletters,
        ),
      },
    },
    newsletters: {
      enabled: asBoolean(
        (newsletters as any).enabled,
        base.newsletters.enabled,
      ),
      frequency: asNewsletterFrequency(
        (newsletters as any).frequency,
        base.newsletters.frequency,
      ),
    },
    theme: {
      mode: asThemeMode((theme as any).mode, base.theme.mode),
    },
    locale: {
      language: asString((locale as any).language, base.locale.language),
      currency: asString((locale as any).currency, base.locale.currency),
      timezone:
        typeof (locale as any).timezone === 'string'
          ? (locale as any).timezone
          : undefined,
    },
    ui: {
      reduceMotion: asBoolean((ui as any).reduceMotion, base.ui.reduceMotion),
      highContrast: asBoolean((ui as any).highContrast, base.ui.highContrast),
    },
    privacy: {
      showEmail: asBoolean((privacy as any).showEmail, base.privacy.showEmail),
      showPhone: asBoolean((privacy as any).showPhone, base.privacy.showPhone),
      showProfileImage: asBoolean(
        (privacy as any).showProfileImage,
        base.privacy.showProfileImage,
      ),
    },
  };
}

export function mergeProfilePreferences(
  current: unknown,
  patch: unknown,
): UserProfilePreferences {
  const normalizedCurrent = normalizeProfilePreferences(current);
  if (!isPlainObject(patch)) return normalizedCurrent;

  const merged = {
    ...normalizedCurrent,
    ...patch,
    notifications: {
      ...normalizedCurrent.notifications,
      ...(isPlainObject((patch as any).notifications)
        ? (patch as any).notifications
        : {}),
      sms: {
        ...normalizedCurrent.notifications.sms,
        ...(isPlainObject((patch as any).notifications?.sms)
          ? (patch as any).notifications.sms
          : {}),
      },
      email: {
        ...normalizedCurrent.notifications.email,
        ...(isPlainObject((patch as any).notifications?.email)
          ? (patch as any).notifications.email
          : {}),
      },
    },
    newsletters: {
      ...normalizedCurrent.newsletters,
      ...(isPlainObject((patch as any).newsletters)
        ? (patch as any).newsletters
        : {}),
    },
    theme: {
      ...normalizedCurrent.theme,
      ...(isPlainObject((patch as any).theme) ? (patch as any).theme : {}),
    },
    locale: {
      ...normalizedCurrent.locale,
      ...(isPlainObject((patch as any).locale) ? (patch as any).locale : {}),
    },
    ui: {
      ...normalizedCurrent.ui,
      ...(isPlainObject((patch as any).ui) ? (patch as any).ui : {}),
    },
    privacy: {
      ...normalizedCurrent.privacy,
      ...(isPlainObject((patch as any).privacy) ? (patch as any).privacy : {}),
    },
  };

  return normalizeProfilePreferences(merged);
}
