import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Setting } from 'src/setting/entities/setting.entity';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { SettingCryptoService } from 'src/common/utils/setting-crypto.service';
import { OAuthProvider, OAuthProviderSetting } from 'src/setting/entities/oauth-provider-setting.entity';

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

export interface AppleOAuthResolvedConfig {
  config: AppleOAuthRuntimeConfig;
  allowedRoleIds?: string[];
  allowedDomains?: string[];
  profileId?: string;
}

export interface GoogleOAuthResolvedConfig {
  config: GoogleOAuthRuntimeConfig;
  // Role IDs attached to the profile. Descendants should be checked at login time.
  allowedRoleIds?: string[];
  // Optional domain restrictions for this profile.
  allowedDomains?: string[];
  profileId?: string;
}

@Injectable()
export class OAuthCredentialsService {
  private warned = new Set<string>();

  private isUuid(value: string): boolean {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    );
  }

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
    @InjectRepository(OAuthProviderSetting)
    private readonly oauthProviderSettingRepository: Repository<OAuthProviderSetting>,
    private readonly cache: AppCacheService,
    private readonly configService: ConfigService,
    private readonly crypto: SettingCryptoService,
  ) {}

  async getGoogleConfigForContext(
    context: 'admin' | 'customer',
    profileIdOrKey?: string,
  ): Promise<GoogleOAuthResolvedConfig> {
    // Deprecated: Google OAuth is now always selected by profile key/id.
    if (!profileIdOrKey) {
      throw new Error(
        'Google OAuth profile selection is required. No legacy fallback supported.',
      );
    }
    return this.getGoogleProfileConfig(profileIdOrKey);
  }

  async getAppleConfigForContext(
    context: 'admin',
    profileIdOrKey?: string,
  ): Promise<AppleOAuthResolvedConfig> {
    if (profileIdOrKey) {
      return this.getAppleProfileConfig(profileIdOrKey);
    }

    const cfg = await this.getAppleAdminConfig();
    return { config: cfg };
  }

  async getAppleProfileConfig(
    profileIdOrKey: string,
  ): Promise<AppleOAuthResolvedConfig> {
    const resolvedId = await this.cache.remember(
      `settings:oauth:apple:profile:resolve:${profileIdOrKey}`,
      async () => {
        const where = this.isUuid(profileIdOrKey)
          ? ({ id: profileIdOrKey, provider: OAuthProvider.APPLE } as const)
          : ({ key: profileIdOrKey, provider: OAuthProvider.APPLE } as const);

        const profile = await this.oauthProviderSettingRepository.findOne({
          where,
          select: ['id'],
        });

        if (!profile?.id) {
          throw new Error('Apple OAuth profile not found');
        }
        return profile.id;
      },
      { ttlSeconds: 3600 },
    );

    const data = await this.cache.remember(
      `settings:oauth:apple:profile:${resolvedId}:internal`,
      async () => {
        const profile = await this.oauthProviderSettingRepository.findOne({
          where: { id: resolvedId, provider: OAuthProvider.APPLE },
          relations: ['allowedRoles'],
        });

        if (!profile) {
          throw new Error('Apple OAuth profile not found');
        }

        const clientID = profile.clientId?.trim() || undefined;
        const teamID = profile.teamId?.trim() || undefined;
        const keyID = profile.keyId?.trim() || undefined;
        const privateKeyString = this.safeDecrypt(
          `apple-profile:${profile.id}`,
          profile.privateKey || '',
        );
        const callbackURL = profile.callbackUrl?.trim() || '';

        return {
          profileId: profile.id,
          config: {
            clientID,
            teamID,
            keyID,
            privateKeyString: privateKeyString?.trim() || undefined,
            callbackURL,
          },
          allowedRoleIds: (profile.allowedRoles || []).map((r) => r.id),
          allowedDomains: Array.isArray(profile.allowedDomains)
            ? profile.allowedDomains
                .map((d) => String(d).trim().toLowerCase())
                .filter((d) => d.length > 0)
            : undefined,
        } satisfies AppleOAuthResolvedConfig;
      },
      { ttlSeconds: 3600 },
    );

    return data as AppleOAuthResolvedConfig;
  }

  async getGoogleProfileConfig(profileIdOrKey: string): Promise<GoogleOAuthResolvedConfig> {
    // First resolve identifier to a profile id (supports both uuid id and the new key).
    const resolvedId = await this.cache.remember(
      `settings:oauth:google:profile:resolve:${profileIdOrKey}`,
      async () => {
        const where = this.isUuid(profileIdOrKey)
          ? ({ id: profileIdOrKey, provider: OAuthProvider.GOOGLE } as const)
          : ({ key: profileIdOrKey, provider: OAuthProvider.GOOGLE } as const);

        const profile = await this.oauthProviderSettingRepository.findOne({
          where,
          select: ['id'],
        });

        if (!profile?.id) {
          throw new Error('Google OAuth profile not found');
        }
        return profile.id;
      },
      { ttlSeconds: 3600 },
    );

    const data = await this.cache.remember(
      `settings:oauth:google:profile:${resolvedId}:internal`,
      async () => {
        const profile = await this.oauthProviderSettingRepository.findOne({
          where: { id: resolvedId, provider: OAuthProvider.GOOGLE },
          relations: ['allowedRoles'],
        });

        if (!profile) {
          throw new Error('Google OAuth profile not found');
        }

        const clientID = profile.clientId?.trim() || undefined;
        const clientSecret = this.safeDecrypt(
          `google-profile:${profile.id}`,
          profile.clientSecret || '',
        );
        const callbackURL = profile.callbackUrl?.trim() || '';

        return {
          profileId: profile.id,
          config: {
            clientID,
            clientSecret: clientSecret?.trim() || undefined,
            callbackURL,
          },
          allowedRoleIds: (profile.allowedRoles || []).map((r) => r.id),
          allowedDomains: Array.isArray(profile.allowedDomains)
            ? profile.allowedDomains
                .map((d) => String(d).trim().toLowerCase())
                .filter((d) => d.length > 0)
            : undefined,
        } satisfies GoogleOAuthResolvedConfig;
      },
      { ttlSeconds: 3600 },
    );

    return data as GoogleOAuthResolvedConfig;
  }

  // NOTE: legacy Google OAuth fallback methods were removed.
  // Always use getGoogleProfileConfig(profileIdOrKey).

  // Removed: legacy Google OAuth settings fallback (use profile-based config only)

  async getAppleAdminConfig(): Promise<AppleOAuthRuntimeConfig> {
    const defaultCallback = `${this.configService.get<string>(
      'APP_URL',
      'http://localhost:8090',
    )}/api/v1/auth/apple/callback`;

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
      { ttlSeconds: 3600 },
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
