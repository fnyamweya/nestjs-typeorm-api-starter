import { SetMetadata } from '@nestjs/common';
import { PermissionModule } from '../entities/permission.entity';

export const PERMISSIONS_KEY = 'permissions';

export interface PermissionRequirement {
  module: PermissionModule;
  permission: 'create' | 'read' | 'update' | 'delete';
}

export const RequirePermissions = (...permissions: PermissionRequirement[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);
