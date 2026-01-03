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
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { SettingCryptoService } from 'src/common/utils/setting-crypto.service';

@Injectable()
export class SettingService {
  constructor(
    @InjectRepository(Setting)
    private settingRepository: Repository<Setting>,
    private readonly cache: AppCacheService,
    private readonly crypto: SettingCryptoService,
  ) {}

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
          smtpPort: parseInt(this.getSettingValue(settings, 'smtp_port') || '587'),
          smtpSecure: this.getSettingValue(settings, 'smtp_secure') === 'true',
          smtpUsername: this.getSettingValue(settings, 'smtp_username'),
          smtpPassword: this.getSettingValue(settings, 'smtp_password'),
          smtpFromEmail: this.getSettingValue(settings, 'smtp_from_email'),
          smtpFromName: this.getSettingValue(settings, 'smtp_from_name'),
          smtpEnabled: this.getSettingValue(settings, 'smtp_enabled') === 'true',
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
      key === 'whatsapp_webhook_verify_token'
    );
  }

  async createSMSSettings(
    createSMSSettingDto: CreateSMSSettingDto,
  ): Promise<SMSResponseDto> {
    const smsSettings = [
      { key: 'sms_provider', value: createSMSSettingDto.provider },
      { key: 'sms_at_api_key', value: this.crypto.encrypt(createSMSSettingDto.apiKey) },
      { key: 'sms_at_username', value: this.crypto.encrypt(createSMSSettingDto.username) },
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
      { key: 'whatsapp_access_token', value: this.crypto.encrypt(createWhatsappSettingDto.accessToken) },
      { key: 'whatsapp_business_account_id', value: createWhatsappSettingDto.businessAccountId },
      { key: 'whatsapp_phone_number_id', value: createWhatsappSettingDto.phoneNumberId },
      { key: 'whatsapp_app_id', value: createWhatsappSettingDto.appId || '' },
      { key: 'whatsapp_api_version', value: createWhatsappSettingDto.apiVersion || 'v19.0' },
      { key: 'whatsapp_base_url', value: createWhatsappSettingDto.baseUrl || 'https://graph.facebook.com' },
      { key: 'whatsapp_enabled', value: createWhatsappSettingDto.whatsappEnabled.toString() },
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
          provider: this.getSettingValue(settings, 'sms_provider') || 'africastalking',
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
          provider: this.getSettingValue(settings, 'whatsapp_provider') || 'meta',
          businessAccountId: this.getSettingValue(settings, 'whatsapp_business_account_id'),
          phoneNumberId: this.getSettingValue(settings, 'whatsapp_phone_number_id'),
          apiVersion: this.getSettingValue(settings, 'whatsapp_api_version') || 'v19.0',
          baseUrl: this.getSettingValue(settings, 'whatsapp_base_url') || 'https://graph.facebook.com',
          whatsappEnabled: this.getSettingValue(settings, 'whatsapp_enabled') === 'true',
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

      const appSecretValue = existing.find((s) => s.key === 'whatsapp_app_secret')?.value;
      const verifyTokenValue = existing.find((s) => s.key === 'whatsapp_webhook_verify_token')?.value;

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

    const appSecretValue = updated.find((s) => s.key === 'whatsapp_app_secret')?.value;
    const verifyTokenValue = updated.find((s) => s.key === 'whatsapp_webhook_verify_token')?.value;

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
        const keys = ['shipping_enabled', 'shipping_free_threshold', 'shipping_flat_fee'];
        const settings = await this.settingRepository.find({
          where: keys.map((k) => ({ key: k })),
        });

        return {
          shippingEnabled: this.getSettingValue(settings, 'shipping_enabled') === 'true',
          freeThreshold: parseFloat(
            this.getSettingValue(settings, 'shipping_free_threshold') || '0',
          ),
          flatFee: parseFloat(this.getSettingValue(settings, 'shipping_flat_fee') || '50'),
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
          taxRate: parseFloat(this.getSettingValue(settings, 'tax_rate') || '0'),
          createdAt: settings[0]?.createdAt,
          updatedAt: settings[0]?.updatedAt,
        };
      },
      { ttlSeconds: 300 },
    );
  }
}
