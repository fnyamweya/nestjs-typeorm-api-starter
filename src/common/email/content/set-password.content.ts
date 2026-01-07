import type {
  EmailTemplateResult,
  SetPasswordAudience,
  SetPasswordEmailInput,
} from '../email.types';
import { renderSetPasswordTemplate } from '../templates/set-password.template';

const setPasswordAudiences = ['customer', 'admin', 'user'] as const;

export function resolveSetPasswordAudience(
  audience?: SetPasswordAudience,
): SetPasswordAudience {
  if (!audience) return 'user';
  return (setPasswordAudiences as readonly string[]).includes(audience)
    ? audience
    : 'user';
}

export function getSetPasswordEmailContent({
  audience,
  appName,
  link,
  expiresInMinutes,
}: SetPasswordEmailInput): EmailTemplateResult {
  switch (audience) {
    case 'customer':
      return {
        subject: `${appName} account setup`,
        html: renderSetPasswordTemplate({
          title: `${appName} Account Setup`,
          headline: 'Finish setting up your account',
          appName,
          link,
          expiresInMinutes,
          lead: `Welcome to ${appName}. Use the button below to set your password and complete your account setup. This link expires in ${expiresInMinutes} minutes.`,
          footerNote:
            "If you didn't expect this email, you can safely ignore it.",
        }),
      };

    case 'admin':
      return {
        subject: `${appName} admin account setup`,
        html: renderSetPasswordTemplate({
          title: `${appName} Admin Account Setup`,
          headline: 'Set your admin password',
          appName,
          link,
          expiresInMinutes,
          lead: `You've been invited to access ${appName} as staff. Use the button below to set your password. This link expires in ${expiresInMinutes} minutes.`,
          footerNote:
            "If you didn't expect this invite, please ignore this email and contact your administrator.",
        }),
      };

    case 'user':
    default:
      return {
        subject: `${appName} password setup`,
        html: renderSetPasswordTemplate({
          title: `${appName} Password Setup`,
          headline: 'Set your password',
          appName,
          link,
          expiresInMinutes,
          lead: `Use the button below to create or update your password. This link expires in ${expiresInMinutes} minutes.`,
          footerNote:
            'If you did not request this, you can safely ignore this email.',
        }),
      };
  }
}
