import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash, randomBytes } from 'crypto';
import * as argon2 from 'argon2';
import { Repository } from 'typeorm';
import { Role } from '../entities/role.entity';
import {
  Permission,
  PermissionModule,
  PermissionType,
} from '../entities/permission.entity';
import { RolePermission } from '../entities/role-permission.entity';
import { User } from 'src/user/entities/user.entity';
import { AuthProviderType, MfaChannel, UserStatus } from 'src/user/enums';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';
import { buildPasswordSetLink } from 'src/auth/utils/password-set-link.util';
import {
  CacheKey,
  CacheKeyService,
  CacheKeyStatus,
} from '../entities/cache-key.entity';
import { CustomerProfile } from 'src/user/entities/customer-profile.entity';

interface RoleConfig {
  name: string;
  description: string;
  modules: {
    [module: string]: PermissionType[];
  };
  parentName?: string;
}

@Injectable()
export class AuthSeeder {
  constructor(
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>,
    @InjectRepository(RolePermission)
    private rolePermissionRepository: Repository<RolePermission>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(CustomerProfile)
    private customerProfileRepository: Repository<CustomerProfile>,
    @InjectRepository(CacheKey)
    private cacheKeyRepository: Repository<CacheKey>,
    private configService: ConfigService,
    private emailServiceUtils: EmailServiceUtils,
  ) {}

  private getRoleConfigurations(allModules: string[]): RoleConfig[] {
    const allPermissions = Object.values(PermissionType).filter(
      (value) => typeof value === 'string',
    ) as PermissionType[];

    const moduleAccess = Object.fromEntries(
      allModules.map((module) => [module, allPermissions]),
    );
    return [
      {
        name: 'Super Admin',
        description: 'Super Administrator role with full access',
        modules: moduleAccess,
      },
      {
        name: 'Admin',
        description: 'Administrator role with full access',
        modules: moduleAccess,
      },
      {
        name: 'Customer',
        description: 'Customer role with limited access',
        modules: {},
      },
      {
        name: 'Basic Customer',
        description: 'Basic customer role (inherits Customer permissions)',
        modules: {},
        parentName: 'Customer',
      },
    ];
  }

  async seed() {
    // Create all modules' permissions first
    const allModules = Object.values(PermissionModule).filter(
      (value) => typeof value === 'string',
    ) as string[];

    const roleConfigs = this.getRoleConfigurations(allModules);
    const createdRoles: Role[] = [];

    const modulePermissions: { [module: string]: Permission[] } = {};
    for (const module of allModules) {
      modulePermissions[module] = await this.createModulePermissions(module);
    }

    // Create roles and assign permissions dynamically
    // First pass: create parent roles (those without parentName)
    for (const roleConfig of roleConfigs.filter((r) => !r.parentName)) {
      const role = await this.createRole(
        roleConfig.name,
        roleConfig.description,
      );
      createdRoles.push(role);

      await this.assignPermissionsToRoleFromConfig(
        role,
        roleConfig.modules,
        modulePermissions,
      );
    }

    // Second pass: create child roles with parents wired up
    for (const roleConfig of roleConfigs.filter((r) => r.parentName)) {
      const parent = createdRoles.find((r) => r.name === roleConfig.parentName);
      const role = await this.createRole(
        roleConfig.name,
        roleConfig.description,
        parent,
      );
      createdRoles.push(role);

      await this.assignPermissionsToRoleFromConfig(
        role,
        roleConfig.modules,
        modulePermissions,
      );
    }

    // Super Admin user
    const superAdminRole = createdRoles.find((r) => r.name === 'Super Admin');
    const adminRole = createdRoles.find((r) => r.name === 'Admin');
    const customerRole = createdRoles.find(
      (r) => r.name?.toLowerCase?.() === 'customer',
    );
    await this.createSuperAdmin(superAdminRole!);
    if (adminRole) {
      await this.createAdmin(adminRole);
    }

    // Seed a default customer account for local/dev use.
    if (customerRole) {
      await this.upsertSeedCustomer({
        email: 'felixombura+cs@gmail.com',
        phone: '0707033066',
        password: 'customer',
        roleId: customerRole.id,
      });
    }
  }

  private async upsertSeedCustomer(input: {
    email: string;
    phone: string;
    password: string;
    roleId: string;
  }): Promise<void> {
    const existing = await this.userRepository.findOne({
      where: [{ email: input.email } as any, { phone: input.phone } as any],
    });

    const baseProps = {
      email: input.email,
      phone: input.phone,
      roleId: input.roleId,
      authProvider: AuthProviderType.LOCAL,
      isActive: true,
      status: UserStatus.ACTIVE,
      mfaChannel: MfaChannel.EMAIL,
      twoFactorEnabled: false,
    };

    let userId: string;

    if (!existing) {
      const created = await this.userRepository.save(
        this.userRepository.create({
          ...baseProps,
          passwordHash: input.password,
        }),
      );
      userId = created.id;
    } else {
      // Avoid surprising identity changes: only fill in missing values.
      const shouldUpdateEmail = !existing.email;
      const shouldUpdatePhone = !existing.phone;

      if (shouldUpdateEmail) {
        existing.email = input.email;
      }
      if (shouldUpdatePhone) {
        existing.phone = input.phone;
      }

      existing.roleId = existing.roleId || input.roleId;
      existing.isActive = true;
      existing.status = UserStatus.ACTIVE;
      existing.authProvider = AuthProviderType.LOCAL;
      existing.mfaChannel = existing.mfaChannel || MfaChannel.EMAIL;

      // Always reset password to the seeded value (dev convenience).
      existing.passwordHash = input.password;

      const saved = await this.userRepository.save(existing);
      userId = saved.id;
    }

    const profileExists = await this.customerProfileRepository.findOne({
      where: { userId } as any,
    });
    if (!profileExists) {
      await this.customerProfileRepository.save(
        this.customerProfileRepository.create({ userId }),
      );
    }
  }

  private async createRole(
    name: string,
    description: string,
    parent?: Role,
  ): Promise<Role> {
    const existingRole = await this.roleRepository.findOne({
      where: { name },
      relations: ['parent'],
    });

    if (existingRole) {
      if (
        parent &&
        (!existingRole.parent || existingRole.parent.id !== parent.id)
      ) {
        existingRole.parent = parent;
        return this.roleRepository.save(existingRole);
      }
      return existingRole;
    }

    return this.roleRepository.save(
      this.roleRepository.create({ name, description, parent }),
    );
  }

  private async createModulePermissions(module: string): Promise<Permission[]> {
    const permissions: Permission[] = [];
    for (const permissionType of Object.values(PermissionType)) {
      if (typeof permissionType === 'string') {
        const existing = await this.permissionRepository.findOne({
          where: { module, permission: permissionType },
        });
        if (!existing) {
          const p = this.permissionRepository.create({
            module,
            permission: permissionType,
          });
          permissions.push(await this.permissionRepository.save(p));
        } else {
          permissions.push(existing);
        }
      }
    }
    return permissions;
  }

  private async assignPermissionsToRoleFromConfig(
    role: Role,
    moduleConfig: { [module: string]: PermissionType[] },
    modulePermissions: { [module: string]: Permission[] },
  ) {
    for (const [module, allowed] of Object.entries(moduleConfig)) {
      const permissions = modulePermissions[module] || [];
      const filtered = permissions.filter((p) =>
        allowed.includes(p.permission),
      );
      await this.assignPermissionsToRole(role, filtered);
    }
  }

  private async assignPermissionsToRole(role: Role, permissions: Permission[]) {
    for (const permission of permissions) {
      const exists = await this.rolePermissionRepository.findOne({
        where: { roleId: role.id, permissionId: permission.id },
      });
      if (!exists) {
        await this.rolePermissionRepository.save(
          this.rolePermissionRepository.create({
            roleId: role.id,
            permissionId: permission.id,
          }),
        );
      }
    }
  }

  private async createSuperAdmin(role: Role): Promise<void> {
    const email =
      this.configService.get<string>('SUPER_ADMIN_EMAIL') ||
      process.env.SUPER_ADMIN_EMAIL;

    if (!email) {
      throw new Error('SUPER_ADMIN_EMAIL is not configured');
    }

    const existing = await this.userRepository.findOne({ where: { email } });
    if (existing) {
      return;
    }

    const superAdmin = await this.userRepository.save(
      this.userRepository.create({
        email,
        firstName: 'Super',
        lastName: 'Admin',
        phone: '+95912345678',
        roleId: role.id,
        authProvider: AuthProviderType.LOCAL,
        isActive: true,
        status: UserStatus.ACTIVE,
        mfaChannel: MfaChannel.EMAIL,
      }),
    );

    const { token, tokenHash, expiresAt } = this.generatePasswordSetToken();

    await this.cacheKeyRepository.save(
      this.cacheKeyRepository.create({
        userId: superAdmin.id,
        service: CacheKeyService.SET_PASSWORD,
        code: tokenHash,
        expiresAt,
        status: CacheKeyStatus.PENDING,
        attempts: 0,
        maxAttempts: 1,
      }),
    );

    const link = buildPasswordSetLink({
      configService: this.configService,
      token,
      audience: 'admin',
      roleName: role.name,
    });

    try {
      await this.emailServiceUtils.sendSetPasswordLink({
        email,
        link,
        appName: this.configService.get<string>('APP_NAME', 'Application'),
        expiresInMinutes: Math.round(
          (expiresAt.getTime() - Date.now()) / 60000,
        ),
        audience: 'admin',
      });
    } catch (err) {
      // In many dev environments SMTP is not configured.
      // Permissions/roles/users should still seed successfully.

      console.warn(
        '⚠️ Skipping set-password email during seeding:',
        err?.message || err,
      );
    }
  }

  private generatePasswordSetToken() {
    const token = randomBytes(32).toString('hex');
    const tokenHash = this.hashToken(token);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    return { token, tokenHash, expiresAt };
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private async createAdmin(role: Role): Promise<void> {
    const email = 'admin@example.com';
    const existing = await this.userRepository.findOne({ where: { email } });
    if (!existing) {
      const password = 'AdminP@ss123';
      const passwordHash = await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: parseInt(
          this.configService.get<string>('ARGON2_MEMORY_COST') ||
            process.env.ARGON2_MEMORY_COST ||
            '19456',
          10,
        ),
        timeCost: parseInt(
          this.configService.get<string>('ARGON2_TIME_COST') ||
            process.env.ARGON2_TIME_COST ||
            '3',
          10,
        ),
        parallelism: parseInt(
          this.configService.get<string>('ARGON2_PARALLELISM') ||
            process.env.ARGON2_PARALLELISM ||
            '1',
          10,
        ),
        hashLength: parseInt(
          this.configService.get<string>('ARGON2_HASH_LENGTH') ||
            process.env.ARGON2_HASH_LENGTH ||
            '32',
          10,
        ),
      });

      await this.userRepository.save(
        this.userRepository.create({
          email,
          firstName: 'Default',
          lastName: 'Admin',
          phone: '+14155550100',
          roleId: role.id,
          passwordHash,
          authProvider: AuthProviderType.LOCAL,
          isActive: true,
          status: UserStatus.ACTIVE,
          mfaChannel: MfaChannel.EMAIL,
        }),
      );
    }
  }
}
