import { Injectable, ExecutionContext, ServiceUnavailableException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { OAuthCredentialsService } from '../services/oauth-credentials.service';

@Injectable()
export class AdminAppleOAuthGuard extends AuthGuard('admin-apple') {
  constructor(private readonly oauthCredentials: OAuthCredentialsService) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const cfg = await this.oauthCredentials.getAppleAdminConfig();
    if (!cfg.clientID || !cfg.teamID || !cfg.keyID || !cfg.privateKeyString) {
      throw new ServiceUnavailableException('Apple OAuth is not configured');
    }

    // Reuse this config in the strategy.authenticate() call to avoid a second cache hit.
    const req = context.switchToHttp().getRequest();
    if (req) {
      req.__oauthAppleAdminConfig = cfg;
    }

    return (await super.canActivate(context)) as boolean;
  }
}
