export type OAuthProvider = 'google' | 'apple';

export interface OAuthProfile {
  provider: OAuthProvider;
  providerId: string;
  email: string;
  firstName?: string;
  lastName?: string;
  picture?: string;
}
