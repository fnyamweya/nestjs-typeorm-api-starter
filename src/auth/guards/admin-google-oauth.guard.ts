import { Injectable, ExecutionContext, ServiceUnavailableException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { OAuthCredentialsService } from '../services/oauth-credentials.service';

function toBase64Url(input: string): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

@Injectable()
export class AdminGoogleOAuthGuard extends AuthGuard('admin-google') {
  constructor(private readonly oauthCredentials: OAuthCredentialsService) {
    super();
  }

  // Attach `state` so the callback can redirect back to the admin UI.
  getAuthenticateOptions(context: ExecutionContext) {
    const req = context.switchToHttp().getRequest();

    // Only set state on the initial request (callback has `code`).
    const hasCode = Boolean(req?.query?.code);
    if (hasCode) return {};

    const returnTo =
      (typeof req?.query?.returnTo === 'string' && req.query.returnTo) ||
      (typeof req?.query?.redirectTo === 'string' && req.query.redirectTo) ||
      undefined;

    if (!returnTo) return {};

    const payload = toBase64Url(JSON.stringify({ returnTo }));
    return { state: payload };
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const cfg = await this.oauthCredentials.getGoogleAdminConfig();
    if (!cfg.clientID || !cfg.clientSecret) {
      throw new ServiceUnavailableException('Google OAuth is not configured');
    }
    return (await super.canActivate(context)) as boolean;
  }
}
