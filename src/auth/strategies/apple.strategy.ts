import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import PassportApple = require('passport-apple');
type AppleProfile = PassportApple.Profile;
type AppleStrategyOptions = PassportApple.AuthenticateOptions;
import { OAuthProfile } from '../interfaces/oauth-profile.interface';
import { OAuthCredentialsService } from '../services/oauth-credentials.service';

@Injectable()
export class AppleStrategy extends PassportStrategy(
  PassportApple,
  'apple',
) {
  constructor(
    private readonly configService: ConfigService,
    private readonly oauthCredentials: OAuthCredentialsService,
  ) {
    const privateKey = configService
      .get<string>('APPLE_PRIVATE_KEY', '')
      .replace(/\\n/g, '\n');

    const defaultCallback = `${configService.get<string>(
      'APP_URL',
      'http://localhost:8090',
    )}/api/v1/auth/apple/callback`;

    const clientID = configService.get<string>('APPLE_CLIENT_ID');
    const teamID = configService.get<string>('APPLE_TEAM_ID');
    const keyID = configService.get<string>('APPLE_KEY_ID');

    const options: AppleStrategyOptions = {
      clientID: clientID || 'missing-apple-client-id',
      teamID: teamID || 'missing-apple-team-id',
      keyID: keyID || 'missing-apple-key-id',
      privateKeyString: privateKey || 'missing-apple-private-key',
      callbackURL:
        configService.get<string>('APPLE_CALLBACK_URL') || defaultCallback,
      scope: ['name', 'email'],
      passReqToCallback: false,
    };

    super(options);
  }

  authenticate(req: any, options?: any): void {
    const fromGuard = req?.__oauthAppleAdminConfig;
    const cfgPromise = fromGuard
      ? Promise.resolve(fromGuard)
      : this.oauthCredentials.getAppleAdminConfig();

    void cfgPromise
      .then((cfg) => {
        if (!cfg.clientID || !cfg.teamID || !cfg.keyID || !cfg.privateKeyString) {
          // Guard should prevent this path; keep a safe fallback.
          return (this as any).fail('Apple OAuth is not configured', 503);
        }

        const self: any = this;
        self._clientID = cfg.clientID;
        self._teamID = cfg.teamID;
        self._keyID = cfg.keyID;
        self._privateKey = cfg.privateKeyString;
        self._callbackURL = cfg.callbackURL;

        // Some versions keep config in _options
        if (self._options) {
          self._options.clientID = cfg.clientID;
          self._options.teamID = cfg.teamID;
          self._options.keyID = cfg.keyID;
          self._options.privateKeyString = cfg.privateKeyString;
          self._options.callbackURL = cfg.callbackURL;
        }

        const settingIdOrKey = req?.__oauthAppleSettingId;
        const mergedOptions = settingIdOrKey
          ? { ...(options || {}), state: settingIdOrKey }
          : options;

        return super.authenticate(req, mergedOptions);
      })
      .catch((err) => this.error(err));
  }

  validate(
    accessToken: string,
    refreshToken: string,
    idToken: Record<string, any>,
    profile: AppleProfile,
  ): OAuthProfile {
    const email =
      profile?.email || idToken?.email || profile?._json?.email || undefined;

    if (!email) {
      throw new UnauthorizedException('Apple account is missing an email');
    }

    return {
      provider: 'apple',
      providerId: profile.id,
      email: email.toLowerCase(),
      firstName: profile?.name?.firstName,
      lastName: profile?.name?.lastName,
    };
  }
}
