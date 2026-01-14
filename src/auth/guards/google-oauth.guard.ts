import {
  Injectable,
  ExecutionContext,
  ServiceUnavailableException,
  BadRequestException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { OAuthCredentialsService } from '../services/oauth-credentials.service';

type PackedState = {
  sid: string;
  r?: string;
};

@Injectable()
export class GoogleOAuthGuard extends AuthGuard('google') {
  constructor(private readonly oauthCredentials: OAuthCredentialsService) {
    super();
  }

  private packState(input: PackedState): string {
    return Buffer.from(JSON.stringify(input)).toString('base64url');
  }

  private unpackState(state: unknown): PackedState | undefined {
    if (typeof state !== 'string' || state.length === 0) return undefined;
    try {
      const decoded = Buffer.from(state, 'base64url').toString('utf8');
      const parsed = JSON.parse(decoded) as PackedState;
      if (!parsed?.sid || typeof parsed.sid !== 'string') return undefined;
      if (parsed.r !== undefined && typeof parsed.r !== 'string') {
        return { sid: parsed.sid };
      }
      return parsed;
    } catch {
      return undefined;
    }
  }

  getAuthenticateOptions(context: ExecutionContext) {
    const req = context.switchToHttp().getRequest();
    const settingIdOrKey =
      (req?.params?.oauthKey as string | undefined) ||
      (req?.query?.settingId as string | undefined) ||
      (req?.query?.state as string | undefined);

    const redirect = (req?.query?.redirect as string | undefined) || undefined;

    // Preserve callback URL exact-match by using OAuth state (not query params on redirect URI).
    // We pack both the profile selector and the desired redirect into state.
    if (!settingIdOrKey) return {};
    const packed = this.packState({ sid: settingIdOrKey, r: redirect });
    return { state: packed };
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();

    const rawState = req?.query?.state as string | undefined;
    const packed = this.unpackState(rawState);
    const settingIdOrKey =
      packed?.sid ||
      rawState ||
      (req?.params?.oauthKey as string | undefined) ||
      (req?.query?.settingId as string | undefined);

    if (!settingIdOrKey) {
      throw new BadRequestException('Missing google oauth settingId');
    }

    let resolved;
    try {
      resolved = await this.oauthCredentials.getGoogleProfileConfig(
        settingIdOrKey,
      );
    } catch {
      throw new BadRequestException('Invalid google oauth settingId');
    }

    const cfg = resolved.config;
    if (!cfg.clientID || !cfg.clientSecret) {
      throw new ServiceUnavailableException('Google OAuth is not configured');
    }

    // Reuse this config in the strategy.authenticate() call to avoid a second cache hit.
    if (req) {
      req.__oauthGoogleConfig = cfg;
      // Keep the raw identifier (uuid or key) so the strategy can preserve state.
      req.__oauthGoogleSettingId = settingIdOrKey;
      req.__oauthGoogleAllowedRoleIds = resolved.allowedRoleIds;
      req.__oauthGoogleAllowedDomains = (resolved as any).allowedDomains;
      req.__oauthRedirect = packed?.r;
    }

    return (await super.canActivate(context)) as boolean;
  }
}
