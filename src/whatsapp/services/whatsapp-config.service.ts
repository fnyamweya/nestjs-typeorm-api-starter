import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Setting } from 'src/setting/entities/setting.entity';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { SettingCryptoService } from 'src/common/utils/setting-crypto.service';

export interface WhatsappConfig {
  provider: string;
  accessToken: string;
  businessAccountId: string;
  phoneNumberId: string;
  appId?: string;
  webhookVerifyToken?: string;
  appSecret?: string;
  apiVersion: string;
  baseUrl: string;
  enabled: boolean;
}

@Injectable()
export class WhatsappConfigService {
  constructor(
    @InjectRepository(Setting)
    private readonly settingRepository: Repository<Setting>,
    private readonly cache: AppCacheService,
    private readonly configService: ConfigService,
    private readonly crypto: SettingCryptoService,
  ) {}

  async getConfig(): Promise<WhatsappConfig> {
    return this.cache.remember(
      'settings:whatsapp:internal',
      async () => {
        const keys = [
          'whatsapp_provider',
          'whatsapp_access_token',
          'whatsapp_business_account_id',
          'whatsapp_phone_number_id',
          'whatsapp_app_id',
          'whatsapp_webhook_verify_token',
          'whatsapp_app_secret',
          'whatsapp_api_version',
          'whatsapp_base_url',
          'whatsapp_enabled',
        ];

        const settings = await this.settingRepository.find({
          where: keys.map((key) => ({ key })),
        });

        const getValue = (key: string) =>
          settings.find((s) => s.key === key)?.value || '';

        const envValue = (key: string) =>
          this.configService.get<string>(key) ?? process.env[key] ?? '';

        return {
          provider:
            getValue('whatsapp_provider') ||
            envValue('WHATSAPP_PROVIDER') ||
            'meta',
          accessToken:
            this.crypto.decrypt(getValue('whatsapp_access_token')) ||
            envValue('WHATSAPP_ACCESS_TOKEN'),
          businessAccountId:
            getValue('whatsapp_business_account_id') ||
            envValue('WHATSAPP_BUSINESS_ACCOUNT_ID'),
          phoneNumberId:
            getValue('whatsapp_phone_number_id') ||
            envValue('WHATSAPP_PHONE_NUMBER_ID'),
          appId:
            getValue('whatsapp_app_id') ||
            envValue('WHATSAPP_APP_ID') ||
            undefined,
          webhookVerifyToken:
            this.crypto.decrypt(getValue('whatsapp_webhook_verify_token')) ||
            envValue('WHATSAPP_WEBHOOK_VERIFY_TOKEN') ||
            undefined,
          appSecret:
            this.crypto.decrypt(getValue('whatsapp_app_secret')) ||
            envValue('WHATSAPP_APP_SECRET') ||
            undefined,
          apiVersion:
            getValue('whatsapp_api_version') ||
            envValue('WHATSAPP_API_VERSION') ||
            'v19.0',
          baseUrl:
            getValue('whatsapp_base_url') ||
            envValue('WHATSAPP_BASE_URL') ||
            'https://graph.facebook.com',
          enabled:
            (
              getValue('whatsapp_enabled') || envValue('WHATSAPP_ENABLED')
            ).toLowerCase() === 'true',
        };
      },
      { ttlSeconds: 300 },
    );
  }
}
