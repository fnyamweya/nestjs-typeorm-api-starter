import { Injectable, ExecutionContext, ServiceUnavailableException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { OAuthCredentialsService } from '../services/oauth-credentials.service';

@Injectable()
export class AppleOAuthGuard extends AuthGuard('apple') {
  constructor(private readonly oauthCredentials: OAuthCredentialsService) {
    super();
  }

  getAuthenticateOptions(context: ExecutionContext) {
    const req = context.switchToHttp().getRequest();
    const settingIdOrKey =
      (req?.params?.oauthKey as string | undefined) ||
      (req?.query?.settingId as string | undefined) ||
      (req?.query?.state as string | undefined);

    // Preserve callback URL exact-match by using OAuth state.
    return settingIdOrKey ? { state: settingIdOrKey } : {};
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const settingIdOrKey =
      (req?.query?.state as string | undefined) ||
      (req?.params?.oauthKey as string | undefined) ||
      (req?.query?.settingId as string | undefined);

    const resolved = await this.oauthCredentials.getAppleConfigForContext(
      'admin',
      settingIdOrKey,
    );

    const cfg = resolved.config;
    if (!cfg.clientID || !cfg.teamID || !cfg.keyID || !cfg.privateKeyString) {
      throw new ServiceUnavailableException('Apple OAuth is not configured');
    }

    // Reuse this config in the strategy.authenticate() call to avoid a second cache hit.
    if (req) {
      req.__oauthAppleAdminConfig = cfg;
      req.__oauthAppleSettingId = settingIdOrKey;

      // Generic policy fields used by AuthService
      req.__oauthAllowedRoleIds = resolved.allowedRoleIds;
      req.__oauthAllowedDomains = resolved.allowedDomains;
    }

    return (await super.canActivate(context)) as boolean;
  }
}
