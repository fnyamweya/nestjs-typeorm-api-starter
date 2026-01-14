import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  OAuthProvider,
  OAuthProviderSetting,
} from '../entities/oauth-provider-setting.entity';
import { Role } from 'src/auth/entities/role.entity';
import { AppCacheService } from 'src/common/cache/app-cache.service';

@Injectable()
export class OAuthProviderSettingSeeder {
  constructor(
    @InjectRepository(OAuthProviderSetting)
    private oauthProviderSettingRepository: Repository<OAuthProviderSetting>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    private readonly cache: AppCacheService,
    private configService: ConfigService,
  ) {}

  async seed(): Promise<void> {
    await this.seedGoogleProfiles();
  }

  private resolveAppUrl(): string {
    const appUrl =
      this.configService.get<string>('APP_URL') ||
      process.env.APP_URL ||
      'http://localhost:5000';

    return appUrl.replace(/\/+$/, '');
  }

  private async seedGoogleProfiles(): Promise<void> {
    const appUrl = this.resolveAppUrl();

    const superAdmin = await this.roleRepository.findOne({
      where: { name: 'Super Admin' },
    });
    const admin = await this.roleRepository.findOne({ where: { name: 'Admin' } });
    const customer = await this.roleRepository.findOne({
      where: { name: 'Customer' },
    });
    const basicCustomer = await this.roleRepository.findOne({
      where: { name: 'Basic Customer' },
    });

    if (!superAdmin || !admin || !customer || !basicCustomer) {
      // AuthSeeder should run first. Fail loud so ordering is obvious.
      throw new Error(
        'Missing required roles for OAuth profile seeding. Ensure AuthSeeder runs before OAuthProviderSettingSeeder.',
      );
    }

    await this.createGoogleProfileIfMissing({
      key: 'customer',
      name: 'Google OAuth - Customer',
      callbackUrl: `${appUrl}/auth/customer/google/callback`,
      allowedRoles: [customer, basicCustomer],
    });

    await this.createGoogleProfileIfMissing({
      key: 'axis',
      name: 'Google OAuth - Axis',
      callbackUrl: `${appUrl}/auth/axis/google/callback`,
      allowedRoles: [superAdmin, admin],
    });
  }

  private async createGoogleProfileIfMissing(params: {
    key: string;
    name: string;
    callbackUrl: string;
    allowedRoles: Role[];
  }): Promise<void> {
    const key = params.key.trim().toLowerCase();
    const existing = await this.oauthProviderSettingRepository.findOne({
      where: { provider: OAuthProvider.GOOGLE, key },
      relations: ['allowedRoles'],
    });

    if (existing) {
      let changed = false;

      // Always bust cached credential resolution so runtime config stays in sync
      // (cache TTL is long, and OAuth redirects must match immediately).
      await this.cache.del(`settings:oauth:google:profile:resolve:${key}`);
      await this.cache.del(`settings:oauth:google:profile:resolve:${existing.id}`);
      await this.cache.del(`settings:oauth:google:profile:${existing.id}:internal`);

      // Keep seeded records aligned with current callback URL format,
      // but do NOT overwrite secrets or client id.
      if (existing.callbackUrl !== params.callbackUrl) {
        existing.callbackUrl = params.callbackUrl;
        changed = true;
      }
      if (existing.name !== params.name) {
        existing.name = params.name;
        changed = true;
      }

      if (changed) {
        await this.oauthProviderSettingRepository.save(existing);
        console.log(
          `Updated Google OAuth profile: provider=google key=${key} (callbackUrl/name)`,
        );
      } else {
        console.log(
          `Google OAuth profile already exists: provider=google key=${key}`,
        );
      }
      return;
    }

    const created = await this.oauthProviderSettingRepository.save(
      this.oauthProviderSettingRepository.create({
        provider: OAuthProvider.GOOGLE,
        key,
        name: params.name,
        // Placeholder; you said you'll fill in the API key/clientId later.
        clientId: 'YOUR_GOOGLE_CLIENT_ID',
        clientSecret: null,
        callbackUrl: params.callbackUrl,
        allowedRoles: params.allowedRoles,
        allowedDomains: undefined,
      }),
    );

    // Bust caches for newly created profile.
    await this.cache.del(`settings:oauth:google:profile:resolve:${key}`);
    await this.cache.del(`settings:oauth:google:profile:resolve:${created.id}`);
    await this.cache.del(`settings:oauth:google:profile:${created.id}:internal`);

    console.log(`Created Google OAuth profile: provider=google key=${key}`);
  }
}
