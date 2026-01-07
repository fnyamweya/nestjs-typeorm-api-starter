import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Job } from 'bullmq';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { QueueService } from 'src/queue/queue.service';
import {
  CacheKey,
  CacheKeyService,
  CacheKeyStatus,
} from '../entities/cache-key.entity';
import { User } from 'src/user/entities/user.entity';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';
import { SmsServiceUtils } from 'src/common/utils/sms-service.utils';
import { WhatsappMessageService } from 'src/whatsapp/services/whatsapp-message.service';
import { ConfigService } from '@nestjs/config';
import { MfaChannel } from 'src/user/enums';

export const AUTH_OTP_QUEUE = 'auth';
export const AUTH_OTP_JOB_SEND_TWO_FACTOR = 'send-two-factor-code';
export const AUTH_OTP_JOB_SEND_RESET_PASSWORD = 'send-reset-password-code';

export type SendOtpJobData = {
  cacheKeyId: string;
  channel?: MfaChannel;
};

@Injectable()
export class AuthOtpWorkerService implements OnModuleInit {
  private readonly logger = new Logger(AuthOtpWorkerService.name);

  constructor(
    private readonly queueService: QueueService,
    @InjectRepository(CacheKey)
    private readonly cacheKeyRepository: Repository<CacheKey>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly emailServiceUtils: EmailServiceUtils,
    private readonly smsServiceUtils: SmsServiceUtils,
    private readonly whatsappMessageService: WhatsappMessageService,
    private readonly configService: ConfigService,
  ) {}

  async onModuleInit() {
    if (process.env.NODE_ENV === 'test') {
      return;
    }

    this.queueService.createWorker<SendOtpJobData, { delivered: string[] }>(
      AUTH_OTP_QUEUE,
      async (job: Job<SendOtpJobData>) => {
        if (job.name === AUTH_OTP_JOB_SEND_TWO_FACTOR) {
          await this.handleSendTwoFactor(job.data);
          return { delivered: ['queued'] };
        }

        if (job.name === AUTH_OTP_JOB_SEND_RESET_PASSWORD) {
          await this.handleSendResetPassword(job.data);
          return { delivered: ['queued'] };
        }

        return { delivered: [] };
      },
      { concurrency: 10 },
    );

    await this.queueService.getQueueEvents(AUTH_OTP_QUEUE);
    this.logger.log(`Auth OTP worker started for queue '${AUTH_OTP_QUEUE}'`);
  }

  private normalizeWhatsappTo(value: string): string {
    return (value || '').replace(/\D/g, '');
  }

  private async handleSendTwoFactor(data: SendOtpJobData): Promise<void> {
    const cacheKey = await this.cacheKeyRepository.findOne({
      where: { id: data.cacheKeyId },
    });

    if (!cacheKey) {
      this.logger.warn(`2FA OTP cacheKey not found: ${data.cacheKeyId}`);
      return;
    }

    if (cacheKey.service !== CacheKeyService.TWO_FACTOR) {
      this.logger.warn(`CacheKey ${cacheKey.id} is not TWO_FACTOR`);
      return;
    }

    if (cacheKey.status !== CacheKeyStatus.PENDING) {
      return;
    }

    if (new Date() > cacheKey.expiresAt) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      return;
    }

    const user = await this.userRepository.findOne({
      where: { id: cacheKey.userId },
    });
    if (!user) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      return;
    }

    const code = cacheKey.code;
    const expiresInMinutes = Math.max(
      1,
      Math.round((cacheKey.expiresAt.getTime() - Date.now()) / 60000),
    );

    const canEmail = Boolean(user.email);
    const canPhone = Boolean(user.phone);

    if (!canEmail && !canPhone) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      return;
    }

    const channel = data.channel || user.mfaChannel || MfaChannel.EMAIL;
    const appName = this.configService.get<string>('APP_NAME', 'Application');

    const deliveries: { channel: string; ok: boolean }[] = [];

    if (canEmail) {
      try {
        const displayName =
          [user.firstName, user.lastName].filter(Boolean).join(' ').trim() ||
          user.email ||
          user.phone;

        await this.emailServiceUtils.sendTwoFactorCode({
          code,
          email: user.email,
          userName: displayName,
          fromUsername: this.configService.get<string>('EMAIL_FROM_NAME', ''),
          expiresIn: expiresInMinutes,
        });

        deliveries.push({ channel: 'email', ok: true });
      } catch {
        deliveries.push({ channel: 'email', ok: false });
      }
    }

    if (canPhone) {
      const to = this.normalizeWhatsappTo(user.phone);
      const phoneMessage = `Your ${appName} verification code is ${code}. It expires in ${expiresInMinutes} minutes.`;

      let whatsappSent = false;
      try {
        if (to) {
          await this.whatsappMessageService.send({
            to,
            type: 'text',
            text: phoneMessage,
          });
          whatsappSent = true;
          deliveries.push({ channel: 'whatsapp', ok: true });
        }
      } catch {
        deliveries.push({ channel: 'whatsapp', ok: false });
      }

      const shouldTrySms = channel === MfaChannel.SMS || !whatsappSent;
      if (shouldTrySms) {
        try {
          await this.smsServiceUtils.sendTwoFactorCodeSMS({
            to: user.phone,
            code,
            expiresIn: expiresInMinutes,
          });
          deliveries.push({ channel: 'sms', ok: true });
        } catch {
          deliveries.push({ channel: 'sms', ok: false });
        }
      }
    }

    if (!deliveries.some((d) => d.ok)) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);

      throw new Error(`Failed to deliver 2FA code for user ${user.id}`);
    }
  }

  private async handleSendResetPassword(data: SendOtpJobData): Promise<void> {
    const cacheKey = await this.cacheKeyRepository.findOne({
      where: { id: data.cacheKeyId },
    });

    if (!cacheKey) {
      this.logger.warn(`Reset OTP cacheKey not found: ${data.cacheKeyId}`);
      return;
    }

    if (cacheKey.service !== CacheKeyService.RESET_PASSWORD) {
      this.logger.warn(`CacheKey ${cacheKey.id} is not RESET_PASSWORD`);
      return;
    }

    if (cacheKey.status !== CacheKeyStatus.PENDING) {
      return;
    }

    if (new Date() > cacheKey.expiresAt) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      return;
    }

    const user = await this.userRepository.findOne({
      where: { id: cacheKey.userId },
    });
    if (!user) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      return;
    }

    if (!user.email && !user.phone) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      return;
    }

    const code = cacheKey.code;
    const expiresInMinutes = Math.max(
      1,
      Math.round((cacheKey.expiresAt.getTime() - Date.now()) / 60000),
    );

    const displayName =
      [user.firstName, user.lastName].filter(Boolean).join(' ').trim() ||
      user.email ||
      user.phone;

    // Always email reset code when email exists
    if (user.email) {
      await this.emailServiceUtils.sendForgotPasswordResetCode({
        code,
        email: user.email,
        userName: displayName,
        fromUsername: this.configService.get<string>('EMAIL_FROM_NAME', ''),
        expiresIn: expiresInMinutes,
      });
    }

    // Also deliver via phone channels when phone exists (best-effort)
    if (user.phone) {
      const appName = this.configService.get<string>('APP_NAME', 'Application');
      const to = this.normalizeWhatsappTo(user.phone);
      const phoneMessage = `Your ${appName} password reset code is ${code}. It expires in ${expiresInMinutes} minutes.`;

      let whatsappSent = false;
      try {
        if (to) {
          await this.whatsappMessageService.send({
            to,
            type: 'text',
            text: phoneMessage,
          });
          whatsappSent = true;
        }
      } catch {
        // best-effort
      }

      if (!whatsappSent) {
        try {
          await this.smsServiceUtils.sendSms({
            to: user.phone,
            message: phoneMessage,
          });
        } catch {
          // best-effort
        }
      }
    }
  }
}
