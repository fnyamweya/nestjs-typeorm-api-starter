import { Injectable, ExecutionContext, ServiceUnavailableException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { OAuthCredentialsService } from '../services/oauth-credentials.service';

@Injectable()
export class AdminGoogleOAuthGuard extends AuthGuard('admin-google') {
  constructor(private readonly oauthCredentials: OAuthCredentialsService) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const cfg = await this.oauthCredentials.getGoogleAdminConfig();
    if (!cfg.clientID || !cfg.clientSecret) {
      throw new ServiceUnavailableException('Google OAuth is not configured');
    }

    // Reuse this config in the strategy.authenticate() call to avoid a second cache hit.
    const req = context.switchToHttp().getRequest();
    if (req) {
      req.__oauthGoogleAdminConfig = cfg;
    }

    return (await super.canActivate(context)) as boolean;
  }
}
