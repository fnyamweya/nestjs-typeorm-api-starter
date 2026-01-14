import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository, ILike } from 'typeorm';
import { JwtService } from '@nestjs/jwt';

import axios from 'axios';

import { createTestApp, truncateDb } from './e2e/bootstrap';
import { OAuthProvider, OAuthProviderSetting } from '../src/setting/entities/oauth-provider-setting.entity';
import { Role } from '../src/auth/entities/role.entity';
import { User } from '../src/user/entities/user.entity';
import { SettingCryptoService } from '../src/common/utils/setting-crypto.service';
import { GoogleOAuthGuard } from '../src/auth/guards/google-oauth.guard';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('Google OAuth (e2e)', () => {
  let app: INestApplication;
  let oauthSettingRepo: Repository<OAuthProviderSetting>;
  let roleRepo: Repository<Role>;
  let userRepo: Repository<User>;
  let crypto: SettingCryptoService;
  let jwtService: JwtService;

  let customerProfileSetting: OAuthProviderSetting;
  let adminProfileSetting: OAuthProviderSetting;

  const customerKey = 'e2e-customer';
  const adminKey = 'e2e-admin';

  // Mutable “mock guard” inputs that tests can tweak.
  let mockAdminEmail = 'superadmin@x.com';
  let mockAdminProviderId = 'google-sub-123';
  let mockAdminAllowedDomains: string[] | undefined;
  let mockAdminAllowedRoleIds: string[] | undefined;

  beforeAll(async () => {
    const t = await createTestApp({
      override: (builder) => {
        builder.overrideGuard(GoogleOAuthGuard).useValue({
          canActivate: async (ctx: any) => {
            const req = ctx.switchToHttp().getRequest();

            // Simulate passport strategy output
            req.user = {
              provider: 'google',
              providerId: mockAdminProviderId,
              email: mockAdminEmail,
              firstName: 'Super',
              lastName: 'Admin',
            };

            // Simulate guard-attached policy info (role + domain constraints)
            req.__oauthAllowedDomains = mockAdminAllowedDomains;
            req.__oauthAllowedRoleIds = mockAdminAllowedRoleIds;

            return true;
          },
        });
      },
    });

    app = t.app;

    await truncateDb(t.ds);

    // Seed only what we need for auth.
    const settingSeeder = app.get(
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      require('../src/setting/seeders/setting.seeder').SettingSeeder,
    );
    const authSeeder = app.get(
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      require('../src/auth/seeders/auth.seeder').AuthSeeder,
    );
    await settingSeeder.seed();
    await authSeeder.seed();

    oauthSettingRepo = app.get(getRepositoryToken(OAuthProviderSetting));
    roleRepo = app.get(getRepositoryToken(Role));
    userRepo = app.get(getRepositoryToken(User));
    crypto = app.get(SettingCryptoService);
    jwtService = app.get(JwtService);

    const customerRole = await roleRepo.findOne({
      where: [{ name: 'customer' }, { name: ILike('customer') }],
    });
    if (!customerRole) throw new Error('Seeded customer role not found');

    const superAdminRole = await roleRepo.findOne({
      where: [{ name: 'super admin' }, { name: ILike('super admin') }],
    });
    if (!superAdminRole) throw new Error('Seeded super admin role not found');

    // Create a role-scoped OAuth profile for customers.
    customerProfileSetting = await oauthSettingRepo.save(
      oauthSettingRepo.create({
        provider: OAuthProvider.GOOGLE,
        key: customerKey,
        name: 'E2E Customer Google OAuth',
        clientId: 'customer-client-id',
        clientSecret: crypto.encrypt('customer-client-secret'),
        callbackUrl: 'http://localhost/customer/google/callback',
        allowedDomains: ['x.com'],
        allowedRoles: [customerRole],
      }),
    );

    // Create a role-scoped OAuth profile for admins/super-admins.
    adminProfileSetting = await oauthSettingRepo.save(
      oauthSettingRepo.create({
        provider: OAuthProvider.GOOGLE,
        key: adminKey,
        name: 'E2E Admin Google OAuth',
        clientId: 'admin-client-id',
        clientSecret: crypto.encrypt('admin-client-secret'),
        callbackUrl: 'http://localhost/auth/google/callback',
        allowedDomains: ['x.com'],
        allowedRoles: [superAdminRole],
      }),
    );

    // Ensure an existing super-admin user exists for the admin OAuth callback test.
    const existing = await userRepo.findOne({ where: { email: mockAdminEmail } });
    if (!existing) {
      await userRepo.save(
        userRepo.create({
          email: mockAdminEmail,
          phone: '+254700000999',
          roleId: superAdminRole.id,
          isActive: true,
        } as any),
      );
    }

    // Configure mock guard policy defaults (tied to the admin profile we created)
    mockAdminAllowedDomains = adminProfileSetting.allowedDomains;
    mockAdminAllowedRoleIds = adminProfileSetting.allowedRoles.map((r) => r.id);
  }, 120000);

  afterAll(async () => {
    if (app) await app.close();
  });

  beforeEach(() => {
    mockedAxios.post.mockReset();
    mockedAxios.get.mockReset();
  });

  it('stores OAuth profile secrets encrypted at rest', async () => {
    const reloaded = await oauthSettingRepo.findOne({
      where: { id: customerProfileSetting.id },
    });
    expect(reloaded).toBeDefined();
    expect(reloaded!.clientSecret).toBeDefined();
    expect(reloaded!.clientSecret).toMatch(/^enc:v1:/);
  });

  it('customer google exchange succeeds for allowed domain', async () => {
    mockedAxios.post.mockResolvedValue({
      data: { id_token: 'test-id-token' },
    } as any);

    mockedAxios.get.mockResolvedValue({
      data: {
        aud: 'customer-client-id',
        sub: 'google-sub-customer-1',
        email: 'customer@x.com',
        email_verified: 'true',
        given_name: 'Customer',
        family_name: 'User',
      },
    } as any);

    const res = await request(app.getHttpServer())
      .post('/auth/customer/google/exchange')
      .send({ code: 'dummy-code', settingId: customerProfileSetting.id })
      .expect(200);

    expect(res.body.success).toBe(true);
    expect(res.body.data).toBeDefined();
    expect(res.body.data.accessToken).toBeDefined();
    expect(res.body.data.refreshToken).toBeDefined();
  });

  it('customer google exchange rejects disallowed domain', async () => {
    mockedAxios.post.mockResolvedValue({
      data: { id_token: 'test-id-token' },
    } as any);

    mockedAxios.get.mockResolvedValue({
      data: {
        aud: 'customer-client-id',
        sub: 'google-sub-customer-2',
        email: 'customer@y.com',
        email_verified: true,
      },
    } as any);

    const res = await request(app.getHttpServer())
      .post('/auth/customer/google/exchange')
      .send({ code: 'dummy-code', settingId: customerProfileSetting.id })
      .expect(401);

    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain('domain');
  });

  it('admin google callback succeeds for allowed domain + role', async () => {
    // Mock guard already sets a super-admin user + domain x.com.
    const res = await request(app.getHttpServer())
      .get(`/auth/${adminKey}/google/callback`)
      .expect(200);

    expect(res.body.success).toBe(true);
    expect(res.body.data).toBeDefined();
    expect(res.body.data.accessToken).toBeDefined();
    expect(res.body.data.refreshToken).toBeDefined();

    // Access token should be a valid JWT with the expected subject.
    const decoded: any = jwtService.decode(res.body.data.accessToken);
    expect(decoded).toBeDefined();
    expect(decoded.sub).toBeDefined();
  });

  it('admin google callback rejects disallowed domain', async () => {
    mockAdminEmail = 'superadmin@not-allowed.com';

    const res = await request(app.getHttpServer())
      .get(`/auth/${adminKey}/google/callback`)
      .expect(401);

    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain('domain');

    // Restore for any subsequent tests.
    mockAdminEmail = 'superadmin@x.com';
  });
});
