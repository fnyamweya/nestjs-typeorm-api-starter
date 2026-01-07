import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Setting } from 'src/setting/entities/setting.entity';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { SettingCryptoService } from 'src/common/utils/setting-crypto.service';

export interface GoogleOAuthRuntimeConfig {
  clientID?: string;
  clientSecret?: string;
  callbackURL: string;
}

export interface AppleOAuthRuntimeConfig {
  clientID?: string;
  teamID?: string;
  keyID?: string;
  privateKeyString?: string;
  callbackURL: string;
}

@Injectable()
export class OAuthCredentialsService {
  private warned = new Set<string>();

  private safeDecrypt(provider: string, value: string): string | undefined {
    if (!value) return undefined;
    try {
      return this.crypto.decrypt(value);
    } catch (err: any) {
      const key = `${provider}:decrypt`;
      if (!this.warned.has(key)) {
        this.warned.add(key);
        console.warn(
          `Unable to decrypt ${provider} OAuth secret from DB settings. Ensure ENCRYPTION_KEY is set and matches the key used to encrypt the secret.`,
        );
      }
      return undefined;
    }
  }

  constructor(
    @InjectRepository(Setting)
    private readonly settingRepository: Repository<Setting>,
    private readonly cache: AppCacheService,
    private readonly configService: ConfigService,
    private readonly crypto: SettingCryptoService,
  ) {}

  async getGoogleAdminConfig(): Promise<GoogleOAuthRuntimeConfig> {
    const defaultCallback = `${this.configService.get<string>(
      'APP_URL',
      'http://localhost:8090',
    )}/api/auth/admin/google/callback`;

    const fromDb = await this.cache.remember(
      'settings:oauth:google:internal',
      async () => {
        const keys = [
          'oauth_google_client_id',
          'oauth_google_client_secret',
          'oauth_google_callback_url',
        ];

        const settings = await this.settingRepository.find({
          where: keys.map((key) => ({ key })),
        });

        const getRaw = (key: string) =>
          settings.find((s) => s.key === key)?.value || '';

        const clientID = getRaw('oauth_google_client_id') || undefined;
        const encClientSecret = getRaw('oauth_google_client_secret') || '';
        const clientSecret = this.safeDecrypt('google', encClientSecret);
        const callbackURL = getRaw('oauth_google_callback_url') || undefined;

        return {
          clientID: clientID?.trim() || undefined,
          clientSecret: clientSecret?.trim() || undefined,
          callbackURL: callbackURL?.trim() || undefined,
        };
      },
      { ttlSeconds: 300 },
    );

    const envClientID = this.configService.get<string>('GOOGLE_CLIENT_ID');
    const envClientSecret = this.configService.get<string>(
      'GOOGLE_CLIENT_SECRET',
    );
    const envCallbackURL = this.configService.get<string>('GOOGLE_CALLBACK_URL');

    const resolved: GoogleOAuthRuntimeConfig = {
      clientID: fromDb.clientID || envClientID || undefined,
      clientSecret: fromDb.clientSecret || envClientSecret || undefined,
      callbackURL:
        fromDb.callbackURL || envCallbackURL || defaultCallback,
    };

    if ((!resolved.clientID || !resolved.clientSecret) && !this.warned.has('google')) {
      this.warned.add('google');
      console.warn(
        'Google OAuth credentials are not configured. Admin Google login will not function until credentials are set (env vars or Settings).',
      );
    }

    return resolved;
  }

  async getAppleAdminConfig(): Promise<AppleOAuthRuntimeConfig> {
    const defaultCallback = `${this.configService.get<string>(
      'APP_URL',
      'http://localhost:8090',
    )}/api/auth/admin/apple/callback`;

    const fromDb = await this.cache.remember(
      'settings:oauth:apple:internal',
      async () => {
        const keys = [
          'oauth_apple_client_id',
          'oauth_apple_team_id',
          'oauth_apple_key_id',
          'oauth_apple_private_key',
          'oauth_apple_callback_url',
        ];

        const settings = await this.settingRepository.find({
          where: keys.map((key) => ({ key })),
        });

        const getRaw = (key: string) =>
          settings.find((s) => s.key === key)?.value || '';

        const clientID = getRaw('oauth_apple_client_id') || undefined;
        const teamID = getRaw('oauth_apple_team_id') || undefined;
        const keyID = getRaw('oauth_apple_key_id') || undefined;
        const encPrivateKey = getRaw('oauth_apple_private_key') || '';
        const privateKeyString = this.safeDecrypt('apple', encPrivateKey);
        const callbackURL = getRaw('oauth_apple_callback_url') || undefined;

        return {
          clientID: clientID?.trim() || undefined,
          teamID: teamID?.trim() || undefined,
          keyID: keyID?.trim() || undefined,
          privateKeyString: privateKeyString || undefined,
          callbackURL: callbackURL?.trim() || undefined,
        };
      },
      { ttlSeconds: 300 },
    );

    const envPrivateKey = (this.configService.get<string>('APPLE_PRIVATE_KEY', '') || '').replace(
      /\\n/g,
      '\n',
    );

    const resolved: AppleOAuthRuntimeConfig = {
      clientID: fromDb.clientID || this.configService.get<string>('APPLE_CLIENT_ID') || undefined,
      teamID: fromDb.teamID || this.configService.get<string>('APPLE_TEAM_ID') || undefined,
      keyID: fromDb.keyID || this.configService.get<string>('APPLE_KEY_ID') || undefined,
      privateKeyString: (fromDb.privateKeyString || envPrivateKey || undefined)?.replace(
        /\\n/g,
        '\n',
      ),
      callbackURL:
        fromDb.callbackURL || this.configService.get<string>('APPLE_CALLBACK_URL') || defaultCallback,
    };

    if (
      (!resolved.clientID ||
        !resolved.teamID ||
        !resolved.keyID ||
        !resolved.privateKeyString) &&
      !this.warned.has('apple')
    ) {
      this.warned.add('apple');
      console.warn(
        'Apple OAuth credentials are not fully configured. Admin Apple login will remain disabled until credentials are set (env vars or Settings).',
      );
    }

    return resolved;
  }
}
