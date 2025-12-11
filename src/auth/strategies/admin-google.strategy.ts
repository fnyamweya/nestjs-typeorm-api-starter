import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Strategy, Profile, StrategyOptions } from 'passport-google-oauth20';
import { OAuthAdminProfile } from '../interfaces/oauth-admin-profile.interface';

@Injectable()
export class AdminGoogleStrategy extends PassportStrategy(
  Strategy,
  'admin-google',
) {
  constructor(private readonly configService: ConfigService) {
    const defaultCallback = `${configService.get<string>(
      'APP_URL',
      'http://localhost:8090',
    )}/api/auth/admin/google/callback`;

    const clientID = configService.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = configService.get<string>('GOOGLE_CLIENT_SECRET');

    if (!clientID || !clientSecret) {
      // eslint-disable-next-line no-console
      console.warn(
        'Google OAuth credentials are not configured. Admin Google login will not function until GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set.',
      );
    }

    const options: StrategyOptions = {
      clientID: clientID || 'missing-google-client-id',
      clientSecret: clientSecret || 'missing-google-client-secret',
      callbackURL:
        configService.get<string>('GOOGLE_CALLBACK_URL') || defaultCallback,
      scope: ['email', 'profile'],
    };

    super(options);
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
      firstName: profile.name?.givenName || profile.displayName?.split(' ')?.[0],
      lastName:
        profile.name?.familyName || profile.displayName?.split(' ')?.slice(1).join(' '),
      picture: profile.photos?.[0]?.value,
    };
  }
}
