import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Role } from '../entities/role.entity';
import { Permission, PermissionType } from '../entities/permission.entity';
import { RolePermission } from '../entities/role-permission.entity';
import { User } from 'src/user/entities/user.entity';

interface RoleConfig {
  name: string;
  description: string;
  modules: {
    [module: string]: PermissionType[];
  };
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
    ];
  }

  async seed() {
    // Create all modules' permissions first
    const allModules = [
      'Users',
      'Roles',
      'Permissions',
      'Activity Logs',
      'Settings',
      'Reporting',
      'Products',
      'Banners',
      'Site Configs',
    ];

    const roleConfigs = this.getRoleConfigurations(allModules);
    const createdRoles: Role[] = [];

    const modulePermissions: { [module: string]: Permission[] } = {};
    for (const module of allModules) {
      modulePermissions[module] = await this.createModulePermissions(module);
    }

    // Create roles and assign permissions dynamically
    for (const roleConfig of roleConfigs) {
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

    // Super Admin user
    const superAdminRole = createdRoles.find((r) => r.name === 'Super Admin');
    await this.createSuperAdmin(superAdminRole!);
  }

  private async createRole(name: string, description: string): Promise<Role> {
    const existingRole = await this.roleRepository.findOne({ where: { name } });
    if (existingRole) return existingRole;
    return this.roleRepository.save(
      this.roleRepository.create({ name, description }),
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
    const email = 'superadmin@gmail.com';
    const existing = await this.userRepository.findOne({ where: { email } });
    if (!existing) {
      await this.userRepository.save(
        this.userRepository.create({
          email,
          fullName: 'Super Admin',
          phone: '+95912345678',
          roleId: role.id,
          password: 'passwordD123!@#',
        }),
      );
    }
  }
}
