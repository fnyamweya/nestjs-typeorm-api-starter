import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository, ILike } from 'typeorm';
import { JwtService } from '@nestjs/jwt';

import { createTestApp, truncateDb } from './e2e/bootstrap';
import {
  OAuthProvider,
  OAuthProviderSetting,
} from '../src/setting/entities/oauth-provider-setting.entity';
import { Role } from '../src/auth/entities/role.entity';
import { User } from '../src/user/entities/user.entity';
import { SettingCryptoService } from '../src/common/utils/setting-crypto.service';
import { AppleOAuthGuard } from '../src/auth/guards/apple-oauth.guard';

describe('Apple OAuth (e2e)', () => {
  let app: INestApplication;
  let oauthSettingRepo: Repository<OAuthProviderSetting>;
  let roleRepo: Repository<Role>;
  let userRepo: Repository<User>;
  let crypto: SettingCryptoService;
  let jwtService: JwtService;

  let adminProfileSetting: OAuthProviderSetting;

  const adminKey = 'e2e-admin-apple';

  // Mutable “mock guard” inputs that tests can tweak.
  let mockAdminEmail = 'superadmin@x.com';
  let mockAdminProviderId = 'apple-sub-123';
  let mockAdminAllowedDomains: string[] | undefined;
  let mockAdminAllowedRoleIds: string[] | undefined;

  beforeAll(async () => {
    const t = await createTestApp({
      override: (builder) => {
        builder.overrideGuard(AppleOAuthGuard).useValue({
          canActivate: async (ctx: any) => {
            const req = ctx.switchToHttp().getRequest();

            // Simulate passport strategy output
            req.user = {
              provider: 'apple',
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

    const superAdminRole = await roleRepo.findOne({
      where: [{ name: 'super admin' }, { name: ILike('super admin') }],
    });
    if (!superAdminRole) throw new Error('Seeded super admin role not found');

    // Create a role-scoped OAuth profile for admins/super-admins.
    adminProfileSetting = await oauthSettingRepo.save(
      oauthSettingRepo.create({
        provider: OAuthProvider.APPLE,
        key: adminKey,
        name: 'E2E Admin Apple OAuth',
        clientId: 'admin-apple-client-id',
        teamId: 'team-id-1',
        keyId: 'key-id-1',
        privateKey: crypto.encrypt('-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----'),
        callbackUrl: 'http://localhost/auth/apple/callback',
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

  it('stores OAuth profile secrets encrypted at rest', async () => {
    const reloaded = await oauthSettingRepo.findOne({
      where: { id: adminProfileSetting.id },
    });
    expect(reloaded).toBeDefined();
    expect(reloaded!.privateKey).toBeDefined();
    expect(reloaded!.privateKey).toMatch(/^enc:v1:/);
  });

  it('admin apple callback succeeds for allowed domain + role', async () => {
    const res = await request(app.getHttpServer())
      .post(`/auth/${adminKey}/apple/callback`)
      .send({})
      .expect(200);

    expect(res.body.success).toBe(true);
    expect(res.body.data).toBeDefined();
    expect(res.body.data.accessToken).toBeDefined();
    expect(res.body.data.refreshToken).toBeDefined();

    const decoded: any = jwtService.decode(res.body.data.accessToken);
    expect(decoded).toBeDefined();
    expect(decoded.sub).toBeDefined();
  });

  it('admin apple callback rejects disallowed domain', async () => {
    mockAdminEmail = 'superadmin@not-allowed.com';

    const res = await request(app.getHttpServer())
      .post(`/auth/${adminKey}/apple/callback`)
      .send({})
      .expect(401);

    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain('domain');

    // Restore for any subsequent tests.
    mockAdminEmail = 'superadmin@x.com';
  });

  it('admin apple callback rejects disallowed role', async () => {
    const customerRole = await roleRepo.findOne({
      where: [{ name: 'customer' }, { name: ILike('customer') }],
    });
    if (!customerRole) throw new Error('Seeded customer role not found');

    mockAdminAllowedRoleIds = [customerRole.id];

    const res = await request(app.getHttpServer())
      .post(`/auth/${adminKey}/apple/callback`)
      .send({})
      .expect(401);

    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain('authorized');

    // Restore for any subsequent tests.
    mockAdminAllowedRoleIds = adminProfileSetting.allowedRoles.map((r) => r.id);
  });
});
