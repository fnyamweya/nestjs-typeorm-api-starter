import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  PERMISSIONS_KEY,
  PermissionRequirement,
} from '../decorators/permissions.decorator';
import {
  AuthenticatedUser,
  RequestWithUser,
} from '../interfaces/user.interface';
import { PermissionType } from '../entities/permission.entity';
import { DataSource } from 'typeorm';
import { Role } from '../entities/role.entity';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private dataSource: DataSource,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.getAllAndOverride<
      PermissionRequirement[]
    >(PERMISSIONS_KEY, [context.getHandler(), context.getClass()]);

    if (!requiredPermissions) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest<RequestWithUser>();

    if (!user || !user.role) {
      throw new ForbiddenException('Access denied: No permissions');
    }

    // Super Admin bypasses checks
    if (user.role.name?.toLowerCase() === 'super admin') {
      return true;
    }

    const roleWithAncestors = await this.loadRoleWithAncestors(user.role.id);

    if (!roleWithAncestors) {
      throw new ForbiddenException('Access denied: Role not found');
    }

    const effectivePermissions = this.flattenPermissions(roleWithAncestors);

    const hasPermission = requiredPermissions.every((requiredPermission) =>
      this.checkObjectPermission(requiredPermission, effectivePermissions),
    );

    if (!hasPermission) {
      throw new ForbiddenException('Access denied: Insufficient permissions');
    }

    return true;
  }

  private checkObjectPermission(
    requiredPermission: PermissionRequirement,
    permissions: Array<{ module: string; permission: PermissionType }>,
  ): boolean {
    const permissionTypeMap = {
      create: PermissionType.CREATE,
      read: PermissionType.READ,
      update: PermissionType.UPDATE,
      delete: PermissionType.DELETE,
    };

    const requiredPermissionType =
      permissionTypeMap[requiredPermission.permission];

    return permissions.some(
      (p) =>
        p.module === requiredPermission.module.toString() &&
        p.permission === requiredPermissionType,
    );
  }

  private async loadRoleWithAncestors(roleId: string): Promise<Role | null> {
    const roleRepository = this.dataSource.getRepository(Role);

    const role = await roleRepository.findOne({
      where: { id: roleId },
      relations: ['rolePermissions', 'rolePermissions.permission'],
    });

    if (!role) return null;

    const treeRepo = this.dataSource.getTreeRepository(Role);
    return treeRepo.findAncestorsTree(role, {
      relations: ['rolePermissions', 'rolePermissions.permission'],
    });
  }

  private flattenPermissions(role: Role | undefined): Array<{
    module: string;
    permission: PermissionType;
  }> {
    if (!role) return [];

    const direct = role.rolePermissions?.map((rp) => ({
      module: rp.permission.module,
      permission: rp.permission.permission as PermissionType,
    })) || [];

    const parentPerms = this.flattenPermissions(role.parent);

    const combined = [...direct, ...parentPerms];

    // Deduplicate by module+permission
    const seen = new Set<string>();
    const unique: Array<{ module: string; permission: PermissionType }> = [];
    for (const p of combined) {
      const key = `${p.module}:${p.permission}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(p);
      }
    }
    return unique;
  }
}
