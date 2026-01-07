import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { AuthService } from '../auth.service';
import { User } from 'src/user/entities/user.entity';
import { RefreshToken } from '../../entities/refresh-token.entity';
import { UserActivityLog } from 'src/activity-log/entities/user-activity-log.entity';
import {
  CacheKey,
  CacheKeyService,
  CacheKeyStatus,
} from '../../entities/cache-key.entity';
import { CustomerProfile } from 'src/user/entities/customer-profile.entity';
import { AdminProfile } from 'src/user/entities/admin-profile.entity';
import { Role } from '../../entities/role.entity';
import { UserAuthProvider } from '../../entities/user-auth-provider.entity';
import { UserInvite } from '../../entities/user-invite.entity';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { TwoFactorService } from '../two-factor.service';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';
import { SmsServiceUtils } from 'src/common/utils/sms-service.utils';
import { FeatureFlagService } from 'src/feature-flag/feature-flag.service';
import { WhatsappMessageService } from 'src/whatsapp/services/whatsapp-message.service';
import { RateLimitService } from 'src/common/security/rate-limit.service';
import { QueueService } from 'src/queue/queue.service';
import {
  AUTH_OTP_JOB_SEND_RESET_PASSWORD,
  AUTH_OTP_QUEUE,
} from '../../workers/auth-otp.worker';

describe('AuthService (2FA + password reset)', () => {
  let service: AuthService;

  const requestMock: any = {
    get: () => '',
    ip: '127.0.0.1',
    headers: {},
  };

  const userRepository = {
    findOne: jest.fn(),
    save: jest.fn(),
    update: jest.fn(),
    remove: jest.fn(),
    create: jest.fn(),
    delete: jest.fn(),
  };
  const refreshTokenRepository = { findOne: jest.fn(), delete: jest.fn() };
  const userActivityLogRepository = { create: jest.fn(), save: jest.fn() };
  const cacheKeyRepository = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    update: jest.fn(),
  };
  const customerProfileRepository = {
    findOne: jest.fn(),
    save: jest.fn(),
    create: jest.fn(),
  };
  const adminProfileRepository = {
    findOne: jest.fn(),
    save: jest.fn(),
    create: jest.fn(),
  };
  const roleRepository = {
    findOne: jest.fn(),
    manager: { getTreeRepository: jest.fn() },
  };
  const userAuthProviderRepository = {
    findOne: jest.fn(),
    save: jest.fn(),
    create: jest.fn(),
  };
  const userInviteRepository = {
    findOne: jest.fn(),
    save: jest.fn(),
    create: jest.fn(),
  };

  const jwtService = {
    sign: jest.fn().mockReturnValue('jwt'),
    verifyAsync: jest.fn().mockResolvedValue(undefined),
    decode: jest.fn(),
  };

  const configService = { get: jest.fn() };
  const twoFactorService = {
    isTwoFactorEnabled: jest.fn(),
    sendVerificationCode: jest.fn(),
    validateLoginCode: jest.fn(),
  };

  const s3ClientUtils = {};
  const emailServiceUtils = {};
  const smsServiceUtils = {};
  const featureFlagService = { isEnabled: jest.fn().mockResolvedValue(false) };
  const whatsappMessageService = {};
  const rateLimitService = { assertWithinLimit: jest.fn() };
  const queueService = { addJob: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: getRepositoryToken(User), useValue: userRepository },
        {
          provide: getRepositoryToken(RefreshToken),
          useValue: refreshTokenRepository,
        },
        {
          provide: getRepositoryToken(UserActivityLog),
          useValue: userActivityLogRepository,
        },
        { provide: getRepositoryToken(CacheKey), useValue: cacheKeyRepository },
        {
          provide: getRepositoryToken(CustomerProfile),
          useValue: customerProfileRepository,
        },
        {
          provide: getRepositoryToken(AdminProfile),
          useValue: adminProfileRepository,
        },
        { provide: getRepositoryToken(Role), useValue: roleRepository },
        {
          provide: getRepositoryToken(UserAuthProvider),
          useValue: userAuthProviderRepository,
        },
        {
          provide: getRepositoryToken(UserInvite),
          useValue: userInviteRepository,
        },
        { provide: JwtService, useValue: jwtService },
        { provide: ConfigService, useValue: configService },
        { provide: TwoFactorService, useValue: twoFactorService },
        { provide: S3ClientUtils, useValue: s3ClientUtils },
        { provide: EmailServiceUtils, useValue: emailServiceUtils },
        { provide: SmsServiceUtils, useValue: smsServiceUtils },
        { provide: FeatureFlagService, useValue: featureFlagService },
        { provide: WhatsappMessageService, useValue: whatsappMessageService },
        { provide: RateLimitService, useValue: rateLimitService },
        { provide: QueueService, useValue: queueService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  afterEach(() => jest.resetAllMocks());

  it('returns requiresTwoFactor when enabled and no code provided', async () => {
    jest.spyOn(service as any, 'validateUser').mockResolvedValue({ id: 'u1' });
    jest
      .spyOn(service as any, 'completeLogin')
      .mockResolvedValue({ accessToken: 'a', refreshToken: 'r' });

    twoFactorService.isTwoFactorEnabled.mockResolvedValue(true);

    const result = await service.login(
      { email: 'e', password: 'p' } as any,
      {} as any,
    );

    expect(twoFactorService.sendVerificationCode).toHaveBeenCalledWith('u1');
    expect((service as any).completeLogin).not.toHaveBeenCalled();
    expect(result).toEqual(
      expect.objectContaining({
        requiresTwoFactor: true,
        userId: 'u1',
        twoFactorToken: 'jwt',
      }),
    );
  });

  it('completes login when 2FA code provided and valid', async () => {
    jest.spyOn(service as any, 'validateUser').mockResolvedValue({ id: 'u1' });
    jest
      .spyOn(service as any, 'completeLogin')
      .mockResolvedValue({ accessToken: 'a', refreshToken: 'r' });

    twoFactorService.isTwoFactorEnabled.mockResolvedValue(true);
    twoFactorService.validateLoginCode.mockResolvedValue(true);

    userRepository.findOne.mockResolvedValue({
      id: 'u1',
      isBanned: false,
      isActive: true,
    } as any);

    const result = await service.login(
      { email: 'e', password: 'p', twoFactorCode: '123456' } as any,
      requestMock,
    );

    expect(twoFactorService.validateLoginCode).toHaveBeenCalledWith(
      'u1',
      '123456',
    );
    expect((service as any).completeLogin).toHaveBeenCalled();
    expect(result).toEqual({ accessToken: 'a', refreshToken: 'r' });
  });

  it('verifies using twoFactorToken path', async () => {
    jest
      .spyOn(service as any, 'completeLogin')
      .mockResolvedValue({ accessToken: 'a', refreshToken: 'r' });

    jwtService.decode.mockReturnValue({ userId: 'u1', type: 'LOGIN_2FA' });
    twoFactorService.validateLoginCode.mockResolvedValue(true);
    userRepository.findOne.mockResolvedValue({
      id: 'u1',
      isBanned: false,
      isActive: true,
    } as any);

    const result = await service.verifyTwoFactorAndLogin(
      { twoFactorToken: 'token', code: '123456' },
      requestMock,
    );

    expect(jwtService.verifyAsync).toHaveBeenCalledWith('token');
    expect(twoFactorService.validateLoginCode).toHaveBeenCalledWith(
      'u1',
      '123456',
    );
    expect(result).toEqual({ accessToken: 'a', refreshToken: 'r' });
  });

  it('queues password-reset OTP and expires existing pending', async () => {
    userRepository.findOne.mockResolvedValue({
      id: 'u1',
      email: 'user@example.com',
    } as any);

    userActivityLogRepository.create.mockReturnValue({} as any);
    userActivityLogRepository.save.mockResolvedValue(undefined);

    cacheKeyRepository.findOne.mockResolvedValueOnce({
      id: 'old',
      userId: 'u1',
      service: CacheKeyService.RESET_PASSWORD,
      status: CacheKeyStatus.PENDING,
    });

    cacheKeyRepository.save.mockResolvedValueOnce(undefined); // expire old

    cacheKeyRepository.create.mockImplementation((x: any) => ({
      id: 'ck1',
      ...x,
    }));
    cacheKeyRepository.save.mockResolvedValueOnce({ id: 'ck1' }); // save new

    await service.passwordResetOTPSend(
      { identifier: 'user@example.com' } as any,
      requestMock,
    );

    expect(rateLimitService.assertWithinLimit).toHaveBeenCalledTimes(2);

    expect(queueService.addJob).toHaveBeenCalledWith(
      AUTH_OTP_QUEUE,
      AUTH_OTP_JOB_SEND_RESET_PASSWORD,
      { cacheKeyId: 'ck1' },
      expect.objectContaining({
        jobId: expect.stringContaining('reset:u1:ck1'),
      }),
    );
  });

  it('rate-limits password-reset OTP by phone identifier', async () => {
    userRepository.findOne.mockResolvedValue({
      id: 'u1',
      phone: '+254712345678',
    } as any);

    userActivityLogRepository.create.mockReturnValue({} as any);
    userActivityLogRepository.save.mockResolvedValue(undefined);

    cacheKeyRepository.findOne.mockResolvedValueOnce(null);
    cacheKeyRepository.create.mockImplementation((x: any) => ({
      id: 'ck1',
      ...x,
    }));
    cacheKeyRepository.save.mockResolvedValueOnce({ id: 'ck1' });

    await service.passwordResetOTPSend(
      { identifier: '+254 712-345-678' } as any,
      requestMock,
    );

    expect(rateLimitService.assertWithinLimit).toHaveBeenCalledWith(
      expect.objectContaining({ key: 'otp:reset:cooldown:phone:254712345678' }),
    );
    expect(rateLimitService.assertWithinLimit).toHaveBeenCalledWith(
      expect.objectContaining({ key: 'otp:reset:burst:phone:254712345678' }),
    );
  });

  it('returns resetToken after password reset OTP verification', async () => {
    cacheKeyRepository.findOne.mockResolvedValue({
      id: 'ck1',
      userId: 'u1',
      service: CacheKeyService.RESET_PASSWORD,
      status: CacheKeyStatus.PENDING,
      code: '123456',
      expiresAt: new Date(Date.now() + 60_000),
      attempts: 0,
      maxAttempts: 3,
    });

    cacheKeyRepository.save.mockResolvedValue(undefined);
    jwtService.sign.mockReturnValue('resetJwt');

    const res = await service.verifyPasswordResetOTPCode({
      userId: 'u1',
      code: '123456',
    } as any);

    expect(res).toEqual({ userId: 'u1', resetToken: 'resetJwt' });
  });
});
