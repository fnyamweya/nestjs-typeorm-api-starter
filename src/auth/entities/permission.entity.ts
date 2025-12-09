import {
  Entity,
  Column,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
  PrimaryColumn,
  BeforeInsert,
  BeforeUpdate,
} from 'typeorm';
import { RolePermission } from './role-permission.entity';
import { v4 as uuidv4 } from 'uuid';

export enum PermissionType {
  CREATE = 'CREATE',
  READ = 'READ',
  UPDATE = 'UPDATE',
  DELETE = 'DELETE',
}

export enum PermissionModule {
  USERS = 'Users',
  ROLES = 'Roles',
  PERMISSIONS = 'Permissions',
  ACTIVITY_LOGS = 'Activity Logs',
  SETTINGS = 'Settings',
  REPORTING = 'Reporting',
  PRODUCTS = 'Products',
  BANNERS = 'Banners',
  CONTACT_INFOS = 'Contact Infos',
}

@Entity('permissions')
export class Permission {
  @PrimaryColumn('uuid')
  id: string;

  @Column()
  module: string;

  @Column({ type: 'varchar' })
  permission: PermissionType;

  @OneToMany(
    () => RolePermission,
    (rolePermission) => rolePermission.permission,
  )
  rolePermissions: RolePermission[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @BeforeInsert()
  @BeforeUpdate()
  generateUUID() {
    if (!this.id) {
      this.id = uuidv4();
    }
  }
}
