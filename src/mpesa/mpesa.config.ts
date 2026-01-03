export interface MpesaDarajaConfig {
  env: 'sandbox' | 'production';
  consumerKey: string;
  consumerSecret: string;

  /**
   * Typically PayBill or Till number used for C2B.
   */
  shortcode: string;

  /**
   * Required for B2C/B2B.
   */
  initiatorName: string;
  securityCredential: string;

  /**
   * Publicly reachable base URL for Daraja callbacks.
   * Example: https://api.myapp.com
   */
  callbackBaseUrl: string;
}

export function getDarajaBaseUrl(env: MpesaDarajaConfig['env']): string {
  return env === 'production'
    ? 'https://api.safaricom.co.ke'
    : 'https://sandbox.safaricom.co.ke';
}
