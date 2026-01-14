import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Strategy, Profile, StrategyOptions } from 'passport-google-oauth20';
import { OAuthProfile } from '../interfaces/oauth-profile.interface';
import { OAuthCredentialsService } from '../services/oauth-credentials.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(
  Strategy,
  'google',
) {
  constructor(
    private readonly configService: ConfigService,
    private readonly oauthCredentials: OAuthCredentialsService,
  ) {
    // Legacy env/config fallback removed. Strategy config is set dynamically in authenticate().
    super({ clientID: 'placeholder', clientSecret: 'placeholder', callbackURL: 'placeholder', scope: ['email', 'profile'] });
  }

  authenticate(req: any, options?: any): void {
    const fromGuard = req?.__oauthGoogleConfig;
    const cfgPromise = fromGuard
      ? Promise.resolve(fromGuard)
      : Promise.reject(new Error('Google OAuth profile config required'));

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

        // Guard may provide a packed state (e.g., includes redirect). Don't override it.
        return super.authenticate(req, options);
      })
      .catch((err) => this.error(err));
  }

  validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
  ): OAuthProfile {
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
