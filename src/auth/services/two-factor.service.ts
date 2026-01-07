import {
  Injectable,
  BadRequestException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/user/entities/user.entity';
import * as crypto from 'crypto';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';
import { SmsServiceUtils } from 'src/common/utils/sms-service.utils';
import { WhatsappMessageService } from 'src/whatsapp/services/whatsapp-message.service';
import {
  CacheKey,
  CacheKeyService,
  CacheKeyStatus,
} from '../entities/cache-key.entity';
import { ConfigService } from '@nestjs/config';
import { verifyPassword } from 'src/common/utils/password.util';
import { MfaChannel } from 'src/user/enums';
import { QueueService } from 'src/queue/queue.service';
import { RateLimitService } from 'src/common/security/rate-limit.service';
import {
  AUTH_OTP_JOB_SEND_TWO_FACTOR,
  AUTH_OTP_QUEUE,
} from '../workers/auth-otp.worker';

@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name);

  constructor(
    @InjectRepository(CacheKey)
    private cacheKeyRepository: Repository<CacheKey>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private emailServiceUtils: EmailServiceUtils,
    private smsServiceUtils: SmsServiceUtils,
    private whatsappMessageService: WhatsappMessageService,
    private configService: ConfigService,
    private readonly queueService: QueueService,
    private readonly rateLimitService: RateLimitService,
  ) {}

  private normalizeWhatsappTo(value: string): string {
    return (value || '').replace(/\D/g, '');
  }

  async enableTwoFactor(
    userId: string,
    email: string | undefined,
    channel: MfaChannel = MfaChannel.EMAIL,
  ): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    const targetChannel = channel || MfaChannel.EMAIL;

    if (targetChannel === MfaChannel.EMAIL) {
      const targetEmail = email || user.email;
      if (!targetEmail) {
        throw new BadRequestException('Email is required for email-based MFA');
      }
      if (email && user.email !== email) {
        user.email = email;
        await this.userRepository.save(user);
      }
    } else {
      if (!user.phone) {
        throw new BadRequestException(
          'Phone number is required for SMS-based MFA',
        );
      }
    }

    user.mfaChannel = targetChannel;
    await this.userRepository.save(user);

    await this.sendVerificationCode(userId, targetChannel);
    this.logger.log(
      `2FA verification code sent to user ${userId} via ${targetChannel}`,
    );
  }

  async verifyTwoFactor(userId: string, code: string): Promise<boolean> {
    const cacheKey = await this.cacheKeyRepository.findOne({
      where: {
        userId,
        service: CacheKeyService.TWO_FACTOR,
        status: CacheKeyStatus.PENDING,
      },
      order: { createdAt: 'DESC' },
    });

    if (!cacheKey) {
      throw new BadRequestException(
        'No pending two-factor authentication code found',
      );
    }

    // Check if code has expired
    if (new Date() > cacheKey.expiresAt) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      throw new BadRequestException('Verification code has expired');
    }

    // Check if max attempts reached
    if (cacheKey.attempts >= cacheKey.maxAttempts) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      throw new BadRequestException('Maximum verification attempts exceeded');
    }

    // Increment attempts
    cacheKey.attempts += 1;

    // Verify code
    if (cacheKey.code !== code) {
      await this.cacheKeyRepository.save(cacheKey);
      throw new BadRequestException('Invalid verification code');
    }

    // Mark as active
    cacheKey.status = CacheKeyStatus.VERIFIED;
    await this.cacheKeyRepository.save(cacheKey);

    // Update user's 2FA status
    await this.userRepository.update(userId, { twoFactorEnabled: true });

    this.logger.log(`2FA enabled for user ${userId}`);
    return true;
  }

  async disableTwoFactor(userId: string, password: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Verify password (you'll need to implement password verification)
    if (!password) {
      throw new BadRequestException('Password is required to disable 2FA');
    }

    if (!(await this.verifyUserPassword(user, password))) {
      throw new UnauthorizedException('Password does not match');
    }

    // Deactivate all active cache key records
    await this.cacheKeyRepository.update(
      {
        userId,
        service: CacheKeyService.TWO_FACTOR,
        status: CacheKeyStatus.VERIFIED,
      },
      { status: CacheKeyStatus.EXPIRED },
    );

    // Update user's 2FA status
    await this.userRepository.update(userId, {
      twoFactorEnabled: false,
      mfaChannel: MfaChannel.EMAIL,
    });

    this.logger.log(`2FA disabled for user ${userId}`);
  }

  async sendVerificationCode(
    userId: string,
    channelOverride?: MfaChannel,
  ): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    const channel = channelOverride || user.mfaChannel || MfaChannel.EMAIL;

    if (user.mfaChannel !== channel) {
      user.mfaChannel = channel;
      await this.userRepository.save(user);
    }

    // For 2FA-enabled users we deliver codes via email AND phone (WhatsApp/SMS)
    // when possible. At least one channel must succeed.
    const canEmail = Boolean(user.email);
    const canPhone = Boolean(user.phone);

    if (!canEmail && !canPhone) {
      throw new BadRequestException(
        'A valid email or phone number is required for two-factor authentication',
      );
    }

    // Rate limiting: prevent OTP request abuse
    // - Cooldown window: 1 per 30 seconds
    // - Burst window: 3 per 10 minutes
    await this.rateLimitService.assertWithinLimit({
      key: `otp:2fa:cooldown:${userId}`,
      windowSeconds: 30,
      max: 1,
    });
    await this.rateLimitService.assertWithinLimit({
      key: `otp:2fa:burst:${userId}`,
      windowSeconds: 10 * 60,
      max: 3,
    });

    const existingPending = await this.cacheKeyRepository.findOne({
      where: {
        userId,
        service: CacheKeyService.TWO_FACTOR,
        status: CacheKeyStatus.PENDING,
      },
    });

    if (existingPending) {
      existingPending.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(existingPending);
    }

    const code = this.generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    const cacheKey = this.cacheKeyRepository.create({
      userId,
      service: CacheKeyService.TWO_FACTOR,
      code,
      expiresAt,
      status: CacheKeyStatus.PENDING,
      attempts: 0,
      maxAttempts: 3,
    });

    await this.cacheKeyRepository.save(cacheKey);

    // Notifications are delivered asynchronously via queue worker.
    await this.queueService.addJob(
      AUTH_OTP_QUEUE,
      AUTH_OTP_JOB_SEND_TWO_FACTOR,
      {
        cacheKeyId: cacheKey.id,
        channel,
      },
      {
        jobId: `2fa:${userId}:${cacheKey.id}`,
        removeOnComplete: true,
      },
    );

    this.logger.log(`2FA verification code queued for user ${userId}`);
  }

  async validateLoginCode(userId: string, code: string): Promise<boolean> {
    const cacheKey = await this.cacheKeyRepository.findOne({
      where: {
        userId,
        service: CacheKeyService.TWO_FACTOR,
        status: CacheKeyStatus.PENDING,
        code,
      },
    });

    if (!cacheKey) {
      return false;
    }

    if (new Date() > cacheKey.expiresAt) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      return false;
    }

    if (cacheKey.attempts >= cacheKey.maxAttempts) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      return false;
    }

    cacheKey.attempts += 1;

    if (cacheKey.code !== code) {
      await this.cacheKeyRepository.save(cacheKey);
      return false;
    }

    cacheKey.status = CacheKeyStatus.USED;
    await this.cacheKeyRepository.save(cacheKey);

    return true;
  }

  async isTwoFactorEnabled(userId: string): Promise<boolean> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    return user?.twoFactorEnabled || false;
  }

  private async verifyUserPassword(user: User, plainPassword: string) {
    return verifyPassword(user.passwordHash, plainPassword);
  }

  private generateVerificationCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }
}
