export type AdminOAuthProvider = 'google' | 'apple';

export interface OAuthAdminProfile {
  provider: AdminOAuthProvider;
  providerId: string;
  email: string;
  firstName?: string;
  lastName?: string;
  picture?: string;
}
