import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import africastalking from 'africastalking';
import { Setting } from 'src/setting/entities/setting.entity';

interface SMSSettings {
  provider: string;
  apiKey: string;
  username: string;
  senderId?: string;
  smsEnabled: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}

@Injectable()
export class SmsServiceUtils {
  private readonly logger = new Logger(SmsServiceUtils.name);

  constructor(
    @InjectRepository(Setting)
    private settingRepository: Repository<Setting>,
  ) {}

  private async getSMSSettings(): Promise<SMSSettings> {
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

    const provider = this.getSettingValue(settings, 'sms_provider') || 'africastalking';

    return {
      provider,
      apiKey: this.getSettingValue(settings, 'sms_at_api_key'),
      username: this.getSettingValue(settings, 'sms_at_username'),
      senderId: this.getSettingValue(settings, 'sms_sender_id') || undefined,
      smsEnabled: this.getSettingValue(settings, 'sms_enabled') === 'true',
      createdAt: settings[0]?.createdAt,
      updatedAt: settings[0]?.updatedAt,
    };
  }

  private getSettingValue(settings: Setting[], key: string): string {
    const setting = settings.find((s) => s.key === key);
    return setting?.value || '';
  }

  async sendTwoFactorCodeSMS({
    to,
    code,
    expiresIn,
  }: {
    to: string;
    code: string;
    expiresIn: number;
  }): Promise<void> {
    const smsSettings = await this.getSMSSettings();

    if (!smsSettings.smsEnabled) {
      throw new Error('SMS is not enabled');
    }

    if (smsSettings.provider !== 'africastalking') {
      throw new Error('Unsupported SMS provider');
    }

    if (!smsSettings.apiKey || !smsSettings.username) {
      throw new Error('SMS provider credentials are missing');
    }

    const client = africastalking({
      apiKey: smsSettings.apiKey,
      username: smsSettings.username,
    });

    const sms = client.SMS;

    try {
      await sms.send({
        to: [to],
        message: `Your verification code is ${code}. It expires in ${expiresIn} minutes.`,
        from: smsSettings.senderId,
      });
      this.logger.log(`SMS verification code sent to ${to}`);
    } catch (error) {
      this.logger.error(`Failed to send SMS to ${to}`, error as Error);
      throw new Error('Failed to send SMS');
    }
  }
}
