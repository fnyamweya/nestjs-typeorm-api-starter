import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuthOtpWorkerService } from '../auth-otp.worker';
import { QueueService } from 'src/queue/queue.service';
import {
  CacheKey,
  CacheKeyService,
  CacheKeyStatus,
} from '../../entities/cache-key.entity';
import { User } from 'src/user/entities/user.entity';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';
import { SmsServiceUtils } from 'src/common/utils/sms-service.utils';
import { WhatsappMessageService } from 'src/whatsapp/services/whatsapp-message.service';
import { ConfigService } from '@nestjs/config';
import { MfaChannel } from 'src/user/enums';

describe('AuthOtpWorkerService', () => {
  let worker: AuthOtpWorkerService;
  const queueService = { createWorker: jest.fn(), getQueueEvents: jest.fn() };

  const cacheKeyRepository = {
    findOne: jest.fn(),
    save: jest.fn(),
  };

  const userRepository = { findOne: jest.fn() };

  const emailServiceUtils = {
    sendTwoFactorCode: jest.fn(),
    sendForgotPasswordResetCode: jest.fn(),
  };
  const smsServiceUtils = {
    sendTwoFactorCodeSMS: jest.fn(),
    sendSms: jest.fn(),
  };
  const whatsappMessageService = { send: jest.fn() };
  const configService = { get: jest.fn().mockReturnValue('Application') };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthOtpWorkerService,
        { provide: QueueService, useValue: queueService },
        { provide: getRepositoryToken(CacheKey), useValue: cacheKeyRepository },
        { provide: getRepositoryToken(User), useValue: userRepository },
        { provide: EmailServiceUtils, useValue: emailServiceUtils },
        { provide: SmsServiceUtils, useValue: smsServiceUtils },
        { provide: WhatsappMessageService, useValue: whatsappMessageService },
        { provide: ConfigService, useValue: configService },
      ],
    }).compile();

    worker = module.get(AuthOtpWorkerService);
  });

  afterEach(() => jest.resetAllMocks());

  it('falls back to SMS when WhatsApp fails (best-effort)', async () => {
    cacheKeyRepository.findOne.mockResolvedValue({
      id: 'ck1',
      userId: 'u1',
      service: CacheKeyService.TWO_FACTOR,
      status: CacheKeyStatus.PENDING,
      code: '123456',
      expiresAt: new Date(Date.now() + 60_000),
    } as any);

    userRepository.findOne.mockResolvedValue({
      id: 'u1',
      email: 'user@example.com',
      phone: '+254700000000',
      firstName: 'Test',
      lastName: 'User',
      mfaChannel: MfaChannel.SMS,
    } as any);

    emailServiceUtils.sendTwoFactorCode.mockResolvedValue(undefined);
    whatsappMessageService.send.mockRejectedValue(new Error('wa down'));
    smsServiceUtils.sendTwoFactorCodeSMS.mockResolvedValue(undefined);

    await (worker as any).handleSendTwoFactor({
      cacheKeyId: 'ck1',
      channel: MfaChannel.SMS,
    });

    expect(emailServiceUtils.sendTwoFactorCode).toHaveBeenCalled();
    expect(smsServiceUtils.sendTwoFactorCodeSMS).toHaveBeenCalled();
  });

  it('expires cacheKey when all deliveries fail', async () => {
    cacheKeyRepository.findOne.mockResolvedValue({
      id: 'ck1',
      userId: 'u1',
      service: CacheKeyService.TWO_FACTOR,
      status: CacheKeyStatus.PENDING,
      code: '123456',
      expiresAt: new Date(Date.now() + 60_000),
    } as any);

    userRepository.findOne.mockResolvedValue({
      id: 'u1',
      email: 'user@example.com',
      phone: '+254700000000',
      firstName: 'Test',
      lastName: 'User',
      mfaChannel: MfaChannel.EMAIL,
    } as any);

    emailServiceUtils.sendTwoFactorCode.mockRejectedValue(
      new Error('smtp down'),
    );
    whatsappMessageService.send.mockRejectedValue(new Error('wa down'));
    smsServiceUtils.sendTwoFactorCodeSMS.mockRejectedValue(
      new Error('sms down'),
    );

    cacheKeyRepository.save.mockResolvedValue(undefined);

    await expect(
      (worker as any).handleSendTwoFactor({
        cacheKeyId: 'ck1',
        channel: MfaChannel.SMS,
      }),
    ).rejects.toThrow('Failed to deliver 2FA code');

    expect(cacheKeyRepository.save).toHaveBeenCalledWith(
      expect.objectContaining({ status: CacheKeyStatus.EXPIRED }),
    );
  });
});
