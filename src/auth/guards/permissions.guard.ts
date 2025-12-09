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

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.getAllAndOverride<
      PermissionRequirement[]
    >(PERMISSIONS_KEY, [context.getHandler(), context.getClass()]);

    if (!requiredPermissions) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest<RequestWithUser>();

    if (!user || !user.role?.rolePermissions) {
      throw new ForbiddenException('Access denied: No permissions');
    }

    const hasPermission = requiredPermissions.every((requiredPermission) => {
      // Handle new object format
      return this.checkObjectPermission(requiredPermission, user);
    });

    if (!hasPermission) {
      throw new ForbiddenException('Access denied: Insufficient permissions');
    }

    return true;
  }

  private checkObjectPermission(
    requiredPermission: PermissionRequirement,
    user: AuthenticatedUser,
  ): boolean {
    const permissionTypeMap = {
      create: PermissionType.CREATE,
      read: PermissionType.READ,
      update: PermissionType.UPDATE,
      delete: PermissionType.DELETE,
    };

    const requiredPermissionType =
      permissionTypeMap[requiredPermission.permission];

    return !!user?.role?.rolePermissions?.some(
      (rolePermission) =>
        rolePermission.permission.module ===
          requiredPermission.module.toString() &&
        rolePermission.permission.permission === requiredPermissionType,
    );
  }
}
