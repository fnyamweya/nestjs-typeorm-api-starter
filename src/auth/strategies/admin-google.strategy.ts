import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Strategy, Profile, StrategyOptions } from 'passport-google-oauth20';
import { OAuthAdminProfile } from '../interfaces/oauth-admin-profile.interface';
import { OAuthCredentialsService } from '../services/oauth-credentials.service';

@Injectable()
export class AdminGoogleStrategy extends PassportStrategy(
  Strategy,
  'admin-google',
) {
  constructor(
    private readonly configService: ConfigService,
    private readonly oauthCredentials: OAuthCredentialsService,
  ) {
    const callbackBase =
      configService.get<string>('CLIENT_URL') ||
      configService.get<string>('ADMIN_APP_URL') ||
      configService.get<string>('APP_URL') ||
      'http://localhost:5000';

    const defaultCallback = `${callbackBase.replace(/\/+$/, '')}/axis/auth/google/callback`;

    const clientID = configService.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = configService.get<string>('GOOGLE_CLIENT_SECRET');

    const options: StrategyOptions = {
      clientID: clientID || 'missing-google-client-id',
      clientSecret: clientSecret || 'missing-google-client-secret',
      callbackURL:
        configService.get<string>('GOOGLE_CALLBACK_URL') || defaultCallback,
      scope: ['email', 'profile'],
    };

    super(options);
  }

  authenticate(req: any, options?: any): void {
    const fromGuard = req?.__oauthGoogleAdminConfig;
    const cfgPromise = fromGuard
      ? Promise.resolve(fromGuard)
      : this.oauthCredentials.getGoogleAdminConfig();

    void cfgPromise
      .then((cfg) => {
        if (!cfg.clientID || !cfg.clientSecret) {
          // Guard should prevent this path; keep a safe fallback.
          return (this as any).fail('Google OAuth is not configured', 503);
        }

        const self: any = this;

        if (self._oauth2) {
          self._oauth2._clientId = cfg.clientID;
          self._oauth2._clientSecret = cfg.clientSecret;
        }

        if (typeof self._callbackURL === 'string') {
          self._callbackURL = cfg.callbackURL;
        }

        self._clientID = cfg.clientID;
        self._clientSecret = cfg.clientSecret;

        return super.authenticate(req, options);
      })
      .catch((err) => this.error(err));
  }

  validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
  ): OAuthAdminProfile {
    const email = profile.emails?.[0]?.value;

    if (!email) {
      throw new UnauthorizedException(
        'Google account does not expose an email address',
      );
    }

    return {
      provider: 'google',
      providerId: profile.id,
      email: email.toLowerCase(),
      firstName:
        profile.name?.givenName || profile.displayName?.split(' ')?.[0],
      lastName:
        profile.name?.familyName ||
        profile.displayName?.split(' ')?.slice(1).join(' '),
      picture: profile.photos?.[0]?.value,
    };
  }
}
