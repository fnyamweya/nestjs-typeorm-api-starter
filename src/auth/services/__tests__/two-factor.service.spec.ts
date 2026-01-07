import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TwoFactorService } from '../two-factor.service';
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
import { QueueService } from 'src/queue/queue.service';
import { RateLimitService } from 'src/common/security/rate-limit.service';
import {
  AUTH_OTP_JOB_SEND_TWO_FACTOR,
  AUTH_OTP_QUEUE,
} from '../../workers/auth-otp.worker';
import { MfaChannel } from 'src/user/enums';

describe('TwoFactorService', () => {
  let service: TwoFactorService;
  let cacheKeyRepo: Repository<CacheKey>;

  const cacheKeyRepository = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    update: jest.fn(),
  };

  const userRepository = {
    findOne: jest.fn(),
    save: jest.fn(),
    update: jest.fn(),
  };

  const emailServiceUtils = { sendTwoFactorCode: jest.fn() };
  const smsServiceUtils = { sendTwoFactorCodeSMS: jest.fn() };
  const whatsappMessageService = { send: jest.fn() };
  const configService = { get: jest.fn().mockReturnValue('Application') };

  const queueService = { addJob: jest.fn() };
  const rateLimitService = { assertWithinLimit: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TwoFactorService,
        { provide: getRepositoryToken(CacheKey), useValue: cacheKeyRepository },
        { provide: getRepositoryToken(User), useValue: userRepository },
        { provide: EmailServiceUtils, useValue: emailServiceUtils },
        { provide: SmsServiceUtils, useValue: smsServiceUtils },
        { provide: WhatsappMessageService, useValue: whatsappMessageService },
        { provide: ConfigService, useValue: configService },
        { provide: QueueService, useValue: queueService },
        { provide: RateLimitService, useValue: rateLimitService },
      ],
    }).compile();

    service = module.get<TwoFactorService>(TwoFactorService);
    cacheKeyRepo = module.get(getRepositoryToken(CacheKey));
  });

  afterEach(() => jest.resetAllMocks());

  it('enqueues 2FA OTP delivery via queue (rate-limited)', async () => {
    userRepository.findOne.mockResolvedValue({
      id: 'u1',
      email: 'user@example.com',
      phone: '+254700000000',
      mfaChannel: MfaChannel.EMAIL,
    } as any);

    cacheKeyRepository.findOne.mockResolvedValue(null);

    cacheKeyRepository.create.mockImplementation((x: any) => ({
      id: 'ck1',
      ...x,
    }));
    cacheKeyRepository.save.mockImplementation(async (x: any) => x);

    await service.sendVerificationCode('u1', MfaChannel.EMAIL);

    expect(rateLimitService.assertWithinLimit).toHaveBeenCalledTimes(2);

    expect(queueService.addJob).toHaveBeenCalledWith(
      AUTH_OTP_QUEUE,
      AUTH_OTP_JOB_SEND_TWO_FACTOR,
      expect.objectContaining({ cacheKeyId: 'ck1', channel: MfaChannel.EMAIL }),
      expect.objectContaining({ jobId: expect.stringContaining('2fa:u1:ck1') }),
    );
  });

  it('blocks when rate limited', async () => {
    userRepository.findOne.mockResolvedValue({
      id: 'u1',
      email: 'user@example.com',
      phone: '+254700000000',
      mfaChannel: MfaChannel.EMAIL,
    } as any);

    rateLimitService.assertWithinLimit.mockRejectedValueOnce(
      new Error('rate limited'),
    );

    await expect(
      service.sendVerificationCode('u1', MfaChannel.EMAIL),
    ).rejects.toThrow('rate limited');

    expect(queueService.addJob).not.toHaveBeenCalled();
    expect(cacheKeyRepo.save).not.toHaveBeenCalled();
  });
});
