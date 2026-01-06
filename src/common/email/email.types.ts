export type SetPasswordAudience = 'customer' | 'admin' | 'user';

export type EmailTemplateResult = {
  subject: string;
  html: string;
};

export type SetPasswordEmailInput = {
  audience: SetPasswordAudience;
  appName: string;
  link: string;
  expiresInMinutes: number;
};

export type RenderSetPasswordTemplateInput = {
  title: string;
  headline: string;
  appName: string;
  link: string;
  expiresInMinutes: number;
  lead: string;
  footerNote: string;
};

export type RenderUserInviteTemplateInput = {
  inviteLink: string;
  invitedBy: string;
  inviteeName?: string;
};

export type RenderSuperAdminCredentialsTemplateInput = {
  appName: string;
  email: string;
  password: string;
};

export type RenderTwoFactorTemplateInput = {
  code: string;
  userName: string;
  fromUsername: string;
  expiresIn: number;
};

export type RenderResetPasswordCodeTemplateInput = {
  code: string;
  userName: string;
  fromUsername: string;
  expiresIn: number;
};
