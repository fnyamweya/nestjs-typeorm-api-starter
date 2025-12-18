import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { plainToClass } from 'class-transformer';
import { Setting } from '../entities/setting.entity';
import { CreateSMTPDto } from '../dto/create-smtp-setting.dto';
import { SMTPResponseDto } from '../dto/smtp-response.dto';
import { CreateSMSSettingDto } from '../dto/create-sms-setting.dto';
import { SMSResponseDto } from '../dto/sms-response.dto';

@Injectable()
export class SettingService {
  constructor(
    @InjectRepository(Setting)
    private settingRepository: Repository<Setting>,
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

    return this.getSMTPSettings();
  }

  async getSMTPSettings(): Promise<SMTPResponseDto> {
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

    const smtpData = {
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

    return plainToClass(SMTPResponseDto, smtpData);
  }

  private getSettingValue(settings: Setting[], key: string): string {
    const setting = settings.find((s) => s.key === key);
    return setting?.value || '';
  }

  async createSMSSettings(
    createSMSSettingDto: CreateSMSSettingDto,
  ): Promise<SMSResponseDto> {
    const smsSettings = [
      { key: 'sms_provider', value: createSMSSettingDto.provider },
      { key: 'sms_at_api_key', value: createSMSSettingDto.apiKey },
      { key: 'sms_at_username', value: createSMSSettingDto.username },
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

    return this.getSMSSettings();
  }

  async getSMSSettings(): Promise<SMSResponseDto> {
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

    const smsData = {
      provider: this.getSettingValue(settings, 'sms_provider') || 'africastalking',
      username: this.getSettingValue(settings, 'sms_at_username'),
      senderId: this.getSettingValue(settings, 'sms_sender_id'),
      smsEnabled: this.getSettingValue(settings, 'sms_enabled') === 'true',
      createdAt: settings[0]?.createdAt,
      updatedAt: settings[0]?.updatedAt,
    };

    return plainToClass(SMSResponseDto, smsData);
  }

  async getShippingSettings() {
    const keys = ['shipping_enabled', 'shipping_free_threshold', 'shipping_flat_fee'];
    const settings = await this.settingRepository.find({ where: keys.map((k) => ({ key: k })) });

    return {
      shippingEnabled: this.getSettingValue(settings, 'shipping_enabled') === 'true',
      freeThreshold: parseFloat(this.getSettingValue(settings, 'shipping_free_threshold') || '0'),
      flatFee: parseFloat(this.getSettingValue(settings, 'shipping_flat_fee') || '50'),
      createdAt: settings[0]?.createdAt,
      updatedAt: settings[0]?.updatedAt,
    };
  }

  async getTaxSettings() {
    const keys = ['tax_enabled', 'tax_rate'];
    const settings = await this.settingRepository.find({ where: keys.map((k) => ({ key: k })) });

    return {
      taxEnabled: this.getSettingValue(settings, 'tax_enabled') === 'true',
      taxRate: parseFloat(this.getSettingValue(settings, 'tax_rate') || '0'),
      createdAt: settings[0]?.createdAt,
      updatedAt: settings[0]?.updatedAt,
    };
  }
}
