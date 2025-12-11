import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import AppleStrategy = require('passport-apple');
type AppleProfile = AppleStrategy.Profile;
type AppleStrategyOptions = AppleStrategy.AuthenticateOptions;
import { OAuthAdminProfile } from '../interfaces/oauth-admin-profile.interface';

@Injectable()
export class AdminAppleStrategy extends PassportStrategy(
  AppleStrategy,
  'admin-apple',
) {
  constructor(private readonly configService: ConfigService) {
    const privateKey = configService
      .get<string>('APPLE_PRIVATE_KEY', '')
      .replace(/\\n/g, '\n');

    const defaultCallback = `${configService.get<string>(
      'APP_URL',
      'http://localhost:8090',
    )}/api/auth/admin/apple/callback`;

    const clientID = configService.get<string>('APPLE_CLIENT_ID');
    const teamID = configService.get<string>('APPLE_TEAM_ID');
    const keyID = configService.get<string>('APPLE_KEY_ID');

    if (!clientID || !teamID || !keyID || !privateKey) {
      // eslint-disable-next-line no-console
      console.warn(
        'Apple OAuth credentials are not fully configured. Admin Apple login will remain disabled until APPLE_* env vars are set.',
      );
    }

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

  validate(
    accessToken: string,
    refreshToken: string,
    idToken: Record<string, any>,
    profile: AppleProfile,
  ): OAuthAdminProfile {
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
