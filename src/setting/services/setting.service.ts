import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { plainToClass } from 'class-transformer';
import { Setting } from '../entities/setting.entity';
import { CreateSMTPDto } from '../dto/create-smtp-setting.dto';
import { SMTPResponseDto } from '../dto/smtp-response.dto';
import { CreateSMSSettingDto } from '../dto/create-sms-setting.dto';
import { SMSResponseDto } from '../dto/sms-response.dto';
import { CreateWhatsappSettingDto } from '../dto/create-whatsapp-setting.dto';
import { WhatsappResponseDto } from '../dto/whatsapp-response.dto';
import { UpdateWhatsappSecretsDto } from '../dto/update-whatsapp-secrets.dto';
import { WhatsappSecretsResponseDto } from '../dto/whatsapp-secrets-response.dto';
import { CreateS3SettingDto } from '../dto/create-s3-setting.dto';
import { S3ResponseDto } from '../dto/s3-response.dto';
import { UpdateS3SecretsDto } from '../dto/update-s3-secrets.dto';
import { S3SecretsResponseDto } from '../dto/s3-secrets-response.dto';
// Legacy Google OAuth single-setting DTOs removed (profiles are the only supported mechanism).
import { CreateAppleOAuthSettingDto } from '../dto/create-apple-oauth-setting.dto';
import { UpdateAppleOAuthSecretDto } from '../dto/update-apple-oauth-secret.dto';
import { AppleOAuthResponseDto } from '../dto/apple-oauth-response.dto';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { SettingCryptoService } from 'src/common/utils/setting-crypto.service';
import {
  OAuthProviderSetting,
  OAuthProvider,
} from '../entities/oauth-provider-setting.entity';
import { Role } from 'src/auth/entities/role.entity';
import { CreateGoogleOAuthProfileDto } from '../dto/create-google-oauth-profile.dto';
import { UpdateGoogleOAuthProfileDto } from '../dto/update-google-oauth-profile.dto';
import { UpdateGoogleOAuthProfileSecretDto } from '../dto/update-google-oauth-profile-secret.dto';
import { GoogleOAuthProfileResponseDto } from '../dto/google-oauth-profile-response.dto';
import { CreateAppleOAuthProfileDto } from '../dto/create-apple-oauth-profile.dto';
import { UpdateAppleOAuthProfileDto } from '../dto/update-apple-oauth-profile.dto';
import { UpdateAppleOAuthProfileSecretDto } from '../dto/update-apple-oauth-profile-secret.dto';
import { AppleOAuthProfileResponseDto } from '../dto/apple-oauth-profile-response.dto';

@Injectable()
export class SettingService {
  constructor(
    @InjectRepository(Setting)
    private settingRepository: Repository<Setting>,
    @InjectRepository(OAuthProviderSetting)
    private oauthProviderSettingRepository: Repository<OAuthProviderSetting>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    private readonly cache: AppCacheService,
    private readonly crypto: SettingCryptoService,
  ) {}

  private toGoogleOAuthProfileResponse(
    profile: OAuthProviderSetting,
  ): GoogleOAuthProfileResponseDto {
    const key = profile.key ?? undefined;
    return plainToClass(GoogleOAuthProfileResponseDto, {
      id: profile.id,
      key,
      computedCallbackPath: key ? `/auth/${key}/google/callback` : undefined,
      name: profile.name,
      clientId: profile.clientId,
      callbackUrl: profile.callbackUrl,
      allowedRoleIds: (profile.allowedRoles || []).map((r) => r.id),
      allowedDomains: (profile.allowedDomains || undefined) as any,
      hasClientSecret: Boolean(profile.clientSecret),
      createdAt: profile.createdAt,
      updatedAt: profile.updatedAt,
    });
  }

  private toAppleOAuthProfileResponse(
    profile: OAuthProviderSetting,
  ): AppleOAuthProfileResponseDto {
    const key = profile.key ?? undefined;
    return plainToClass(AppleOAuthProfileResponseDto, {
      id: profile.id,
      key,
      computedCallbackPath: key ? `/auth/${key}/apple/callback` : undefined,
      name: profile.name,
      clientId: profile.clientId,
      teamId: profile.teamId,
      keyId: profile.keyId,
      callbackUrl: profile.callbackUrl,
      allowedRoleIds: (profile.allowedRoles || []).map((r) => r.id),
      allowedDomains: (profile.allowedDomains || undefined) as any,
      hasPrivateKey: Boolean(profile.privateKey),
      createdAt: profile.createdAt,
      updatedAt: profile.updatedAt,
    });
  }

  async createAppleOAuthProfile(
    dto: CreateAppleOAuthProfileDto,
  ): Promise<AppleOAuthProfileResponseDto> {
    const roles = await this.roleRepository.find({
      where: dto.allowedRoleIds.map((id) => ({ id })),
    });

    if (roles.length !== dto.allowedRoleIds.length) {
      throw new NotFoundException('One or more roles were not found');
    }

    const entity = this.oauthProviderSettingRepository.create({
      provider: OAuthProvider.APPLE,
      key: dto.key.trim().toLowerCase(),
      name: dto.name.trim(),
      clientId: dto.clientId.trim(),
      teamId: dto.teamId.trim(),
      keyId: dto.keyId.trim(),
      callbackUrl: dto.callbackUrl.trim(),
      // Apple does not use clientSecret in our flow; keep null.
      clientSecret: null,
      privateKey: null,
      allowedRoles: roles,
      allowedDomains:
        dto.allowedDomains
          ?.map((d) => d.trim().toLowerCase())
          .filter((d) => d.length > 0) || undefined,
    });

    const saved = await this.oauthProviderSettingRepository.save(entity);

    await this.cache.del('settings:oauth:apple:profiles');
    await this.cache.del(`settings:oauth:apple:profile:${saved.id}`);
    await this.cache.del(`settings:oauth:apple:profile:${saved.id}:internal`);
    await this.cache.del(`settings:oauth:apple:profile:resolve:${saved.id}`);
    if (saved.key) {
      await this.cache.del(`settings:oauth:apple:profile:resolve:${saved.key}`);
    }

    const reloaded = await this.oauthProviderSettingRepository.findOne({
      where: { id: saved.id, provider: OAuthProvider.APPLE },
      relations: ['allowedRoles'],
    });

    if (!reloaded) {
      throw new NotFoundException('Apple OAuth profile not found');
    }

    return this.toAppleOAuthProfileResponse(reloaded);
  }

  async updateAppleOAuthProfile(
    id: string,
    dto: UpdateAppleOAuthProfileDto,
  ): Promise<AppleOAuthProfileResponseDto> {
    const profile = await this.oauthProviderSettingRepository.findOne({
      where: { id, provider: OAuthProvider.APPLE },
      relations: ['allowedRoles'],
    });

    if (!profile) {
      throw new NotFoundException('Apple OAuth profile not found');
    }

    if (dto.key !== undefined) profile.key = dto.key.trim().toLowerCase();
    if (dto.name !== undefined) profile.name = dto.name.trim();
    if (dto.clientId !== undefined) profile.clientId = dto.clientId.trim();
    if (dto.teamId !== undefined) profile.teamId = dto.teamId.trim();
    if (dto.keyId !== undefined) profile.keyId = dto.keyId.trim();
    if (dto.callbackUrl !== undefined) profile.callbackUrl = dto.callbackUrl.trim();

    if (dto.allowedDomains !== undefined) {
      profile.allowedDomains = dto.allowedDomains
        .map((d) => d.trim().toLowerCase())
        .filter((d) => d.length > 0);
    }

    if (dto.allowedRoleIds !== undefined) {
      const roles = await this.roleRepository.find({
        where: dto.allowedRoleIds.map((rid) => ({ id: rid })),
      });
      if (roles.length !== dto.allowedRoleIds.length) {
        throw new NotFoundException('One or more roles were not found');
      }
      profile.allowedRoles = roles;
    }

    await this.oauthProviderSettingRepository.save(profile);

    await this.cache.del('settings:oauth:apple:profiles');
    await this.cache.del(`settings:oauth:apple:profile:${profile.id}`);
    await this.cache.del(`settings:oauth:apple:profile:${profile.id}:internal`);
    await this.cache.del(`settings:oauth:apple:profile:resolve:${profile.id}`);
    if (profile.key) {
      await this.cache.del(`settings:oauth:apple:profile:resolve:${profile.key}`);
    }

    return this.toAppleOAuthProfileResponse(profile);
  }

  async updateAppleOAuthProfileSecret(
    id: string,
    dto: UpdateAppleOAuthProfileSecretDto,
  ): Promise<AppleOAuthProfileResponseDto> {
    const profile = await this.oauthProviderSettingRepository.findOne({
      where: { id, provider: OAuthProvider.APPLE },
      relations: ['allowedRoles'],
    });

    if (!profile) {
      throw new NotFoundException('Apple OAuth profile not found');
    }

    profile.privateKey = this.crypto.encrypt(dto.privateKey);
    await this.oauthProviderSettingRepository.save(profile);

    await this.cache.del('settings:oauth:apple:profiles');
    await this.cache.del(`settings:oauth:apple:profile:${profile.id}`);
    await this.cache.del(`settings:oauth:apple:profile:${profile.id}:internal`);
    await this.cache.del(`settings:oauth:apple:profile:resolve:${profile.id}`);
    if (profile.key) {
      await this.cache.del(`settings:oauth:apple:profile:resolve:${profile.key}`);
    }

    return this.toAppleOAuthProfileResponse(profile);
  }

  async listAppleOAuthProfiles(): Promise<AppleOAuthProfileResponseDto[]> {
    const data = await this.cache.remember(
      'settings:oauth:apple:profiles',
      async () => {
        const profiles = await this.oauthProviderSettingRepository.find({
          where: { provider: OAuthProvider.APPLE },
          relations: ['allowedRoles'],
          order: { createdAt: 'DESC' },
        });
        return profiles.map((p) => this.toAppleOAuthProfileResponse(p));
      },
      { ttlSeconds: 300 },
    );

    return data as AppleOAuthProfileResponseDto[];
  }

  async getAppleOAuthProfile(id: string): Promise<AppleOAuthProfileResponseDto> {
    const data = await this.cache.remember(
      `settings:oauth:apple:profile:${id}`,
      async () => {
        const profile = await this.oauthProviderSettingRepository.findOne({
          where: { id, provider: OAuthProvider.APPLE },
          relations: ['allowedRoles'],
        });
        if (!profile) {
          throw new NotFoundException('Apple OAuth profile not found');
        }
        return this.toAppleOAuthProfileResponse(profile);
      },
      { ttlSeconds: 300 },
    );

    return plainToClass(AppleOAuthProfileResponseDto, data as any);
  }

  async createGoogleOAuthProfile(
    dto: CreateGoogleOAuthProfileDto,
  ): Promise<GoogleOAuthProfileResponseDto> {
    const roles = await this.roleRepository.find({
      where: dto.allowedRoleIds.map((id) => ({ id })),
    });

    if (roles.length !== dto.allowedRoleIds.length) {
      throw new NotFoundException('One or more roles were not found');
    }

    const entity = this.oauthProviderSettingRepository.create({
      provider: OAuthProvider.GOOGLE,
      key: dto.key.trim().toLowerCase(),
      name: dto.name.trim(),
      clientId: dto.clientId.trim(),
      callbackUrl: dto.callbackUrl.trim(),
      clientSecret: null,
      allowedRoles: roles,
      allowedDomains:
        dto.allowedDomains
          ?.map((d) => d.trim().toLowerCase())
          .filter((d) => d.length > 0) || undefined,
    });

    const saved = await this.oauthProviderSettingRepository.save(entity);

    await this.cache.del('settings:oauth:google:profiles');
    await this.cache.del(`settings:oauth:google:profile:${saved.id}`);
    await this.cache.del(`settings:oauth:google:profile:${saved.id}:internal`);
    await this.cache.del(`settings:oauth:google:profile:resolve:${saved.id}`);
    if (saved.key) {
      await this.cache.del(`settings:oauth:google:profile:resolve:${saved.key}`);
      await this.cache.del(`settings:oauth:google:profile:key:${saved.key}`);
    }

    const reloaded = await this.oauthProviderSettingRepository.findOne({
      where: { id: saved.id, provider: OAuthProvider.GOOGLE },
      relations: ['allowedRoles'],
    });

    if (!reloaded) {
      throw new NotFoundException('Google OAuth profile not found');
    }

    return this.toGoogleOAuthProfileResponse(reloaded);
  }

  async updateGoogleOAuthProfile(
    id: string,
    dto: UpdateGoogleOAuthProfileDto,
  ): Promise<GoogleOAuthProfileResponseDto> {
    const profile = await this.oauthProviderSettingRepository.findOne({
      where: { id, provider: OAuthProvider.GOOGLE },
      relations: ['allowedRoles'],
    });

    if (!profile) {
      throw new NotFoundException('Google OAuth profile not found');
    }

    if (dto.name !== undefined) {
      profile.name = dto.name.trim();
    }
    if (dto.key !== undefined) {
      profile.key = dto.key.trim().toLowerCase();
    }
    if (dto.clientId !== undefined) {
      profile.clientId = dto.clientId.trim();
    }
    if (dto.callbackUrl !== undefined) {
      profile.callbackUrl = dto.callbackUrl.trim();
    }

    if (dto.allowedDomains !== undefined) {
      profile.allowedDomains = dto.allowedDomains
        .map((d) => d.trim().toLowerCase())
        .filter((d) => d.length > 0);
    }

    if (dto.allowedRoleIds !== undefined) {
      const roles = await this.roleRepository.find({
        where: dto.allowedRoleIds.map((rid) => ({ id: rid })),
      });
      if (roles.length !== dto.allowedRoleIds.length) {
        throw new NotFoundException('One or more roles were not found');
      }
      profile.allowedRoles = roles;
    }

    await this.oauthProviderSettingRepository.save(profile);

    await this.cache.del('settings:oauth:google:profiles');
    await this.cache.del(`settings:oauth:google:profile:${profile.id}`);
    await this.cache.del(`settings:oauth:google:profile:${profile.id}:internal`);
    await this.cache.del(`settings:oauth:google:profile:resolve:${profile.id}`);
    if (profile.key) {
      await this.cache.del(`settings:oauth:google:profile:resolve:${profile.key}`);
      await this.cache.del(`settings:oauth:google:profile:key:${profile.key}`);
    }

    return this.toGoogleOAuthProfileResponse(profile);
  }

  async updateGoogleOAuthProfileSecret(
    id: string,
    dto: UpdateGoogleOAuthProfileSecretDto,
  ): Promise<GoogleOAuthProfileResponseDto> {
    const profile = await this.oauthProviderSettingRepository.findOne({
      where: { id, provider: OAuthProvider.GOOGLE },
      relations: ['allowedRoles'],
    });

    if (!profile) {
      throw new NotFoundException('Google OAuth profile not found');
    }

    profile.clientSecret = this.crypto.encrypt(dto.clientSecret);
    await this.oauthProviderSettingRepository.save(profile);

    await this.cache.del('settings:oauth:google:profiles');
    await this.cache.del(`settings:oauth:google:profile:${profile.id}`);
    await this.cache.del(`settings:oauth:google:profile:${profile.id}:internal`);
    await this.cache.del(`settings:oauth:google:profile:resolve:${profile.id}`);
    if (profile.key) {
      await this.cache.del(`settings:oauth:google:profile:resolve:${profile.key}`);
      await this.cache.del(`settings:oauth:google:profile:key:${profile.key}`);
    }

    return this.toGoogleOAuthProfileResponse(profile);
  }

  async listGoogleOAuthProfiles(): Promise<GoogleOAuthProfileResponseDto[]> {
    const data = await this.cache.remember(
      'settings:oauth:google:profiles',
      async () => {
        const profiles = await this.oauthProviderSettingRepository.find({
          where: { provider: OAuthProvider.GOOGLE },
          relations: ['allowedRoles'],
          order: { createdAt: 'DESC' },
        });
        return profiles.map((p) => this.toGoogleOAuthProfileResponse(p));
      },
      { ttlSeconds: 300 },
    );

    return data as GoogleOAuthProfileResponseDto[];
  }

  async getGoogleOAuthProfile(id: string): Promise<GoogleOAuthProfileResponseDto> {
    const data = await this.cache.remember(
      `settings:oauth:google:profile:${id}`,
      async () => {
        const profile = await this.oauthProviderSettingRepository.findOne({
          where: { id, provider: OAuthProvider.GOOGLE },
          relations: ['allowedRoles'],
        });
        if (!profile) {
          throw new NotFoundException('Google OAuth profile not found');
        }
        return this.toGoogleOAuthProfileResponse(profile);
      },
      { ttlSeconds: 300 },
    );

    return plainToClass(GoogleOAuthProfileResponseDto, data as any);
  }

  async getGoogleOAuthProfileByKey(key: string): Promise<GoogleOAuthProfileResponseDto> {
    const normalizedKey = key.trim().toLowerCase();
    const data = await this.cache.remember(
      `settings:oauth:google:profile:key:${normalizedKey}`,
      async () => {
        const profile = await this.oauthProviderSettingRepository.findOne({
          where: { key: normalizedKey, provider: OAuthProvider.GOOGLE },
          relations: ['allowedRoles'],
        });
        if (!profile) {
          throw new NotFoundException('Google OAuth profile not found');
        }
        return this.toGoogleOAuthProfileResponse(profile);
      },
      { ttlSeconds: 300 },
    );

    return plainToClass(GoogleOAuthProfileResponseDto, data as any);
  }

  async createSMTPSettings(
    createSMTPDto: CreateSMTPDto,
  ): Promise<SMTPResponseDto> {
    const smtpSettings = [
      { key: 'smtp_host', value: createSMTPDto.smtpHost },
      { key: 'smtp_port', value: createSMTPDto.smtpPort.toString() },
      { key: 'smtp_secure', value: createSMTPDto.smtpSecure.toString() },
      { key: 'smtp_username', value: createSMTPDto.smtpUsername || '' },
      { key: 'smtp_password', value: createSMTPDto.smtpPassword || '' },
      { key: 'smtp_from_email', value: createSMTPDto.smtpFromEmail },
      { key: 'smtp_from_name', value: createSMTPDto.smtpFromName },
      { key: 'smtp_enabled', value: createSMTPDto.smtpEnabled.toString() },
    ];

    for (const setting of smtpSettings) {
      const existingSetting = await this.settingRepository.findOne({
        where: { key: setting.key },
      });

      if (existingSetting) {
        existingSetting.value = setting.value;
        await this.settingRepository.save(existingSetting);
      } else {
        const newSetting = this.settingRepository.create(setting);
        await this.settingRepository.save(newSetting);
      }
    }

    await this.cache.del('settings:smtp');

    return this.getSMTPSettings();
  }

  async getSMTPSettings(): Promise<SMTPResponseDto> {
    const smtpData = await this.cache.remember(
      'settings:smtp',
      async () => {
        const smtpKeys = [
          'smtp_host',
          'smtp_port',
          'smtp_secure',
          'smtp_username',
          'smtp_password',
          'smtp_from_email',
          'smtp_from_name',
          'smtp_enabled',
        ];

        const settings = await this.settingRepository.find({
          where: smtpKeys.map((key) => ({ key })),
        });

        if (settings.length === 0) {
          throw new NotFoundException('SMTP settings not found');
        }

        return {
          smtpHost: this.getSettingValue(settings, 'smtp_host'),
          smtpPort: parseInt(
            this.getSettingValue(settings, 'smtp_port') || '587',
          ),
          smtpSecure: this.getSettingValue(settings, 'smtp_secure') === 'true',
          smtpUsername: this.getSettingValue(settings, 'smtp_username'),
          smtpPassword: this.getSettingValue(settings, 'smtp_password'),
          smtpFromEmail: this.getSettingValue(settings, 'smtp_from_email'),
          smtpFromName: this.getSettingValue(settings, 'smtp_from_name'),
          smtpEnabled:
            this.getSettingValue(settings, 'smtp_enabled') === 'true',
          createdAt: settings[0]?.createdAt,
          updatedAt: settings[0]?.updatedAt,
        };
      },
      { ttlSeconds: 300 },
    );

    return plainToClass(SMTPResponseDto, smtpData);
  }

  private getSettingValue(settings: Setting[], key: string): string {
    const setting = settings.find((s) => s.key === key);
    const value = setting?.value || '';
    if (this.isSecretKey(key)) {
      return this.crypto.decrypt(value);
    }
    return value;
  }

  private isSecretKey(key: string): boolean {
    return (
      key === 'sms_at_api_key' ||
      key === 'sms_at_username' ||
      key === 'whatsapp_access_token' ||
      key === 'whatsapp_app_secret' ||
      key === 'whatsapp_webhook_verify_token' ||
      key === 's3_access_key_id' ||
      key === 's3_secret_access_key' ||
      key === 'oauth_google_client_secret' ||
      key === 'oauth_google_customer_client_secret' ||
      key === 'oauth_apple_private_key'
    );
  }


  async createAppleOAuthSettings(
    dto: CreateAppleOAuthSettingDto,
  ): Promise<AppleOAuthResponseDto> {
    const entries: Array<{ key: string; value: string }> = [
      { key: 'oauth_apple_client_id', value: dto.clientId.trim() },
      { key: 'oauth_apple_team_id', value: dto.teamId.trim() },
      { key: 'oauth_apple_key_id', value: dto.keyId.trim() },
      { key: 'oauth_apple_callback_url', value: dto.callbackUrl?.trim() || '' },
    ];

    for (const entry of entries) {
      const existingSetting = await this.settingRepository.findOne({
        where: { key: entry.key },
      });

      if (existingSetting) {
        existingSetting.value = entry.value;
        await this.settingRepository.save(existingSetting);
      } else {
        const newSetting = this.settingRepository.create(entry);
        await this.settingRepository.save(newSetting);
      }
    }

    await this.cache.del('settings:oauth:apple');
    await this.cache.del('settings:oauth:apple:internal');

    return this.getAppleOAuthSettings();
  }

  async updateAppleOAuthSecret(
    dto: UpdateAppleOAuthSecretDto,
  ): Promise<AppleOAuthResponseDto> {
    const entry = {
      key: 'oauth_apple_private_key',
      value: this.crypto.encrypt(dto.privateKey),
    };

    const existingSetting = await this.settingRepository.findOne({
      where: { key: entry.key },
    });

    if (existingSetting) {
      existingSetting.value = entry.value;
      await this.settingRepository.save(existingSetting);
    } else {
      const newSetting = this.settingRepository.create(entry);
      await this.settingRepository.save(newSetting);
    }

    await this.cache.del('settings:oauth:apple');
    await this.cache.del('settings:oauth:apple:internal');

    return this.getAppleOAuthSettings();
  }

  async getAppleOAuthSettings(): Promise<AppleOAuthResponseDto> {
    const data = await this.cache.remember(
      'settings:oauth:apple',
      async () => {
        const keys = [
          'oauth_apple_client_id',
          'oauth_apple_team_id',
          'oauth_apple_key_id',
          'oauth_apple_callback_url',
          'oauth_apple_private_key',
        ];

        const settings = await this.settingRepository.find({
          where: keys.map((key) => ({ key })),
        });

        if (settings.length === 0) {
          throw new NotFoundException('Apple OAuth settings not found');
        }

        const getRaw = (key: string) =>
          settings.find((s) => s.key === key)?.value || '';

        const clientId = getRaw('oauth_apple_client_id');
        const teamId = getRaw('oauth_apple_team_id');
        const keyId = getRaw('oauth_apple_key_id');
        const callbackUrl = getRaw('oauth_apple_callback_url');
        const privateKeyStored = getRaw('oauth_apple_private_key');

        return {
          clientId,
          teamId,
          keyId,
          callbackUrl: callbackUrl || undefined,
          hasPrivateKey: Boolean(privateKeyStored),
          createdAt: settings[0]?.createdAt,
          updatedAt: settings[0]?.updatedAt,
        };
      },
      { ttlSeconds: 300 },
    );

    return plainToClass(AppleOAuthResponseDto, data);
  }

  async createS3Settings(dto: CreateS3SettingDto): Promise<S3ResponseDto> {
    const entries: Array<{ key: string; value: string }> = [
      { key: 's3_endpoint', value: dto.s3Endpoint?.trim() || '' },
      { key: 's3_public_base_url', value: dto.s3PublicBaseUrl?.trim() || '' },
      {
        key: 's3_public_dev_base_url',
        value: dto.s3PublicDevBaseUrl?.trim() || '',
      },
      { key: 's3_region', value: dto.s3Region.trim() },
      { key: 's3_bucket_name', value: dto.bucketName.trim() },
      {
        key: 's3_force_path_style',
        value: (dto.forcePathStyle ?? true).toString(),
      },
      { key: 's3_enabled', value: (dto.s3Enabled ?? true).toString() },
    ];

    if (dto.accessKeyId !== undefined) {
      entries.push({
        key: 's3_access_key_id',
        value: this.crypto.encrypt(dto.accessKeyId),
      });
    }

    if (dto.secretAccessKey !== undefined) {
      entries.push({
        key: 's3_secret_access_key',
        value: this.crypto.encrypt(dto.secretAccessKey),
      });
    }

    for (const entry of entries) {
      const existingSetting = await this.settingRepository.findOne({
        where: { key: entry.key },
      });

      if (existingSetting) {
        existingSetting.value = entry.value;
        await this.settingRepository.save(existingSetting);
      } else {
        const newSetting = this.settingRepository.create(entry);
        await this.settingRepository.save(newSetting);
      }
    }

    await this.cache.del('settings:s3');
    await this.cache.del('settings:s3:internal');

    return this.getS3Settings();
  }

  async getS3Settings(): Promise<S3ResponseDto> {
    const data = await this.cache.remember(
      'settings:s3',
      async () => {
        const keys = [
          's3_endpoint',
          's3_public_base_url',
          's3_public_dev_base_url',
          's3_region',
          's3_bucket_name',
          's3_force_path_style',
          's3_enabled',
          's3_access_key_id',
          's3_secret_access_key',
        ];

        const settings = await this.settingRepository.find({
          where: keys.map((key) => ({ key })),
        });

        if (settings.length === 0) {
          throw new NotFoundException('S3 settings not found');
        }

        const getRaw = (key: string) =>
          settings.find((s) => s.key === key)?.value || '';

        const endpoint = getRaw('s3_endpoint');
        const s3PublicBaseUrl = getRaw('s3_public_base_url');
        const s3PublicDevBaseUrl = getRaw('s3_public_dev_base_url');
        const region = getRaw('s3_region');
        const bucketName = getRaw('s3_bucket_name');
        const forcePathStyle =
          (getRaw('s3_force_path_style') || 'true') === 'true';
        const s3Enabled = (getRaw('s3_enabled') || 'true') === 'true';

        const accessKeyIdStored = getRaw('s3_access_key_id');
        const secretKeyStored = getRaw('s3_secret_access_key');

        return {
          s3Endpoint: endpoint,
          s3PublicBaseUrl: s3PublicBaseUrl || undefined,
          s3PublicDevBaseUrl: s3PublicDevBaseUrl || undefined,
          s3Region: region,
          bucketName,
          forcePathStyle,
          s3Enabled,
          hasAccessKeyId: Boolean(accessKeyIdStored),
          hasSecretAccessKey: Boolean(secretKeyStored),
          createdAt: settings[0]?.createdAt,
          updatedAt: settings[0]?.updatedAt,
        };
      },
      { ttlSeconds: 300 },
    );

    return plainToClass(S3ResponseDto, data);
  }

  async updateS3Secrets(
    payload: UpdateS3SecretsDto,
  ): Promise<S3SecretsResponseDto> {
    const entries: Array<{ key: string; value: string }> = [];

    if (payload.accessKeyId !== undefined) {
      entries.push({
        key: 's3_access_key_id',
        value: this.crypto.encrypt(payload.accessKeyId),
      });
    }

    if (payload.secretAccessKey !== undefined) {
      entries.push({
        key: 's3_secret_access_key',
        value: this.crypto.encrypt(payload.secretAccessKey),
      });
    }

    if (entries.length === 0) {
      const existing = await this.settingRepository.find({
        where: [{ key: 's3_access_key_id' }, { key: 's3_secret_access_key' }],
      });

      const accessKeyStored = existing.find(
        (s) => s.key === 's3_access_key_id',
      )?.value;
      const secretKeyStored = existing.find(
        (s) => s.key === 's3_secret_access_key',
      )?.value;

      return {
        hasAccessKeyId: Boolean(accessKeyStored),
        hasSecretAccessKey: Boolean(secretKeyStored),
        updatedAt: existing
          .map((s) => s.updatedAt)
          .filter((d): d is Date => Boolean(d))
          .sort((a, b) => b.getTime() - a.getTime())[0],
      };
    }

    for (const entry of entries) {
      const existingSetting = await this.settingRepository.findOne({
        where: { key: entry.key },
      });

      if (existingSetting) {
        existingSetting.value = entry.value;
        await this.settingRepository.save(existingSetting);
      } else {
        const newSetting = this.settingRepository.create(entry);
        await this.settingRepository.save(newSetting);
      }
    }

    await this.cache.del('settings:s3');
    await this.cache.del('settings:s3:internal');

    const updated = await this.settingRepository.find({
      where: [{ key: 's3_access_key_id' }, { key: 's3_secret_access_key' }],
    });

    const accessKeyStored = updated.find(
      (s) => s.key === 's3_access_key_id',
    )?.value;
    const secretKeyStored = updated.find(
      (s) => s.key === 's3_secret_access_key',
    )?.value;

    return {
      hasAccessKeyId: Boolean(accessKeyStored),
      hasSecretAccessKey: Boolean(secretKeyStored),
      updatedAt: updated
        .map((s) => s.updatedAt)
        .filter((d): d is Date => Boolean(d))
        .sort((a, b) => b.getTime() - a.getTime())[0],
    };
  }

  async createSMSSettings(
    createSMSSettingDto: CreateSMSSettingDto,
  ): Promise<SMSResponseDto> {
    const smsSettings = [
      { key: 'sms_provider', value: createSMSSettingDto.provider },
      {
        key: 'sms_at_api_key',
        value: this.crypto.encrypt(createSMSSettingDto.apiKey),
      },
      {
        key: 'sms_at_username',
        value: this.crypto.encrypt(createSMSSettingDto.username),
      },
      { key: 'sms_sender_id', value: createSMSSettingDto.senderId || '' },
      { key: 'sms_enabled', value: createSMSSettingDto.smsEnabled.toString() },
    ];

    for (const setting of smsSettings) {
      const existingSetting = await this.settingRepository.findOne({
        where: { key: setting.key },
      });

      if (existingSetting) {
        existingSetting.value = setting.value;
        await this.settingRepository.save(existingSetting);
      } else {
        const newSetting = this.settingRepository.create(setting);
        await this.settingRepository.save(newSetting);
      }
    }

    await this.cache.del('settings:sms');

    return this.getSMSSettings();
  }

  async createWhatsappSettings(
    createWhatsappSettingDto: CreateWhatsappSettingDto,
  ): Promise<WhatsappResponseDto> {
    const whatsappSettings = [
      { key: 'whatsapp_provider', value: createWhatsappSettingDto.provider },
      {
        key: 'whatsapp_access_token',
        value: this.crypto.encrypt(createWhatsappSettingDto.accessToken),
      },
      {
        key: 'whatsapp_business_account_id',
        value: createWhatsappSettingDto.businessAccountId,
      },
      {
        key: 'whatsapp_phone_number_id',
        value: createWhatsappSettingDto.phoneNumberId,
      },
      { key: 'whatsapp_app_id', value: createWhatsappSettingDto.appId || '' },
      {
        key: 'whatsapp_api_version',
        value: createWhatsappSettingDto.apiVersion || 'v19.0',
      },
      {
        key: 'whatsapp_base_url',
        value: createWhatsappSettingDto.baseUrl || 'https://graph.facebook.com',
      },
      {
        key: 'whatsapp_enabled',
        value: createWhatsappSettingDto.whatsappEnabled.toString(),
      },
    ];

    for (const setting of whatsappSettings) {
      const existingSetting = await this.settingRepository.findOne({
        where: { key: setting.key },
      });

      if (existingSetting) {
        existingSetting.value = setting.value;
        await this.settingRepository.save(existingSetting);
      } else {
        const newSetting = this.settingRepository.create(setting);
        await this.settingRepository.save(newSetting);
      }
    }

    await this.cache.del('settings:whatsapp');
    await this.cache.del('settings:whatsapp:internal');

    return this.getWhatsappSettings();
  }

  async getSMSSettings(): Promise<SMSResponseDto> {
    const smsData = await this.cache.remember(
      'settings:sms',
      async () => {
        const smsKeys = [
          'sms_provider',
          'sms_at_api_key',
          'sms_at_username',
          'sms_sender_id',
          'sms_enabled',
        ];

        const settings = await this.settingRepository.find({
          where: smsKeys.map((key) => ({ key })),
        });

        if (settings.length === 0) {
          throw new NotFoundException('SMS settings not found');
        }

        return {
          provider:
            this.getSettingValue(settings, 'sms_provider') || 'africastalking',
          username: this.getSettingValue(settings, 'sms_at_username'),
          senderId: this.getSettingValue(settings, 'sms_sender_id'),
          smsEnabled: this.getSettingValue(settings, 'sms_enabled') === 'true',
          createdAt: settings[0]?.createdAt,
          updatedAt: settings[0]?.updatedAt,
        };
      },
      { ttlSeconds: 300 },
    );

    return plainToClass(SMSResponseDto, smsData);
  }

  async getWhatsappSettings(): Promise<WhatsappResponseDto> {
    const whatsappData = await this.cache.remember(
      'settings:whatsapp',
      async () => {
        const whatsappKeys = [
          'whatsapp_provider',
          'whatsapp_access_token',
          'whatsapp_business_account_id',
          'whatsapp_phone_number_id',
          'whatsapp_app_id',
          'whatsapp_api_version',
          'whatsapp_base_url',
          'whatsapp_enabled',
        ];

        const settings = await this.settingRepository.find({
          where: whatsappKeys.map((key) => ({ key })),
        });

        if (settings.length === 0) {
          throw new NotFoundException('WhatsApp settings not found');
        }

        return {
          provider:
            this.getSettingValue(settings, 'whatsapp_provider') || 'meta',
          businessAccountId: this.getSettingValue(
            settings,
            'whatsapp_business_account_id',
          ),
          phoneNumberId: this.getSettingValue(
            settings,
            'whatsapp_phone_number_id',
          ),
          apiVersion:
            this.getSettingValue(settings, 'whatsapp_api_version') || 'v19.0',
          baseUrl:
            this.getSettingValue(settings, 'whatsapp_base_url') ||
            'https://graph.facebook.com',
          whatsappEnabled:
            this.getSettingValue(settings, 'whatsapp_enabled') === 'true',
          createdAt: settings[0]?.createdAt,
          updatedAt: settings[0]?.updatedAt,
        };
      },
      { ttlSeconds: 300 },
    );

    return plainToClass(WhatsappResponseDto, whatsappData);
  }

  async updateWhatsappSecrets(
    payload: UpdateWhatsappSecretsDto,
  ): Promise<WhatsappSecretsResponseDto> {
    const entries: Array<{ key: string; value: string }> = [];

    if (payload.appSecret !== undefined) {
      entries.push({
        key: 'whatsapp_app_secret',
        value: this.crypto.encrypt(payload.appSecret),
      });
    }

    if (payload.webhookVerifyToken !== undefined) {
      entries.push({
        key: 'whatsapp_webhook_verify_token',
        value: this.crypto.encrypt(payload.webhookVerifyToken),
      });
    }

    if (entries.length === 0) {
      const existing = await this.settingRepository.find({
        where: [
          { key: 'whatsapp_app_secret' },
          { key: 'whatsapp_webhook_verify_token' },
        ],
      });

      const appSecretValue = existing.find(
        (s) => s.key === 'whatsapp_app_secret',
      )?.value;
      const verifyTokenValue = existing.find(
        (s) => s.key === 'whatsapp_webhook_verify_token',
      )?.value;

      return {
        hasAppSecret: Boolean(appSecretValue),
        hasWebhookVerifyToken: Boolean(verifyTokenValue),
        updatedAt: existing
          .map((s) => s.updatedAt)
          .filter((d): d is Date => Boolean(d))
          .sort((a, b) => b.getTime() - a.getTime())[0],
      };
    }

    for (const entry of entries) {
      const existingSetting = await this.settingRepository.findOne({
        where: { key: entry.key },
      });

      if (existingSetting) {
        existingSetting.value = entry.value;
        await this.settingRepository.save(existingSetting);
      } else {
        const newSetting = this.settingRepository.create(entry);
        await this.settingRepository.save(newSetting);
      }
    }

    await this.cache.del('settings:whatsapp');
    await this.cache.del('settings:whatsapp:internal');

    const updated = await this.settingRepository.find({
      where: [
        { key: 'whatsapp_app_secret' },
        { key: 'whatsapp_webhook_verify_token' },
      ],
    });

    const appSecretValue = updated.find(
      (s) => s.key === 'whatsapp_app_secret',
    )?.value;
    const verifyTokenValue = updated.find(
      (s) => s.key === 'whatsapp_webhook_verify_token',
    )?.value;

    return {
      hasAppSecret: Boolean(appSecretValue),
      hasWebhookVerifyToken: Boolean(verifyTokenValue),
      updatedAt: updated
        .map((s) => s.updatedAt)
        .filter((d): d is Date => Boolean(d))
        .sort((a, b) => b.getTime() - a.getTime())[0],
    };
  }

  async getShippingSettings() {
    return this.cache.remember(
      'settings:shipping',
      async () => {
        const keys = [
          'shipping_enabled',
          'shipping_free_threshold',
          'shipping_flat_fee',
        ];
        const settings = await this.settingRepository.find({
          where: keys.map((k) => ({ key: k })),
        });

        return {
          shippingEnabled:
            this.getSettingValue(settings, 'shipping_enabled') === 'true',
          freeThreshold: parseFloat(
            this.getSettingValue(settings, 'shipping_free_threshold') || '0',
          ),
          flatFee: parseFloat(
            this.getSettingValue(settings, 'shipping_flat_fee') || '50',
          ),
          createdAt: settings[0]?.createdAt,
          updatedAt: settings[0]?.updatedAt,
        };
      },
      { ttlSeconds: 300 },
    );
  }

  async getTaxSettings() {
    return this.cache.remember(
      'settings:tax',
      async () => {
        const keys = ['tax_enabled', 'tax_rate'];
        const settings = await this.settingRepository.find({
          where: keys.map((k) => ({ key: k })),
        });

        return {
          taxEnabled: this.getSettingValue(settings, 'tax_enabled') === 'true',
          taxRate: parseFloat(
            this.getSettingValue(settings, 'tax_rate') || '0',
          ),
          createdAt: settings[0]?.createdAt,
          updatedAt: settings[0]?.updatedAt,
        };
      },
      { ttlSeconds: 300 },
    );
  }
}
