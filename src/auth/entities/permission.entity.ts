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
  // Core / admin
  USERS = 'Users',
  ROLES = 'Roles',
  PERMISSIONS = 'Permissions',
  AUTHENTICATION = 'Authentication',

  // Platform
  APP = 'App',
  ACTIVITY_LOGS = 'Activity Logs',
  SETTINGS = 'Settings',
  REPORTING = 'Reporting',

  // Commerce
  ORDERS = 'Orders',
  PROMOTIONS = 'Promotions',
  CHANNELS = 'Channels',
  PRICING = 'Pricing',
  CUSTOMER_TIERS = 'Customer Tiers',
  SHIPPING = 'Shipping',
  TAX = 'Tax',

  // Catalog / content
  CATALOG = 'Catalog',
  CURRENCIES = 'Currencies',
  LOCATIONS = 'Locations',
  ADDRESSES = 'Addresses',
  ADDRESS_CONFIG = 'Address Config',
  CUSTOMER_ADDRESSES = 'Customer Addresses',

  // Payments / integrations
  MPESA = 'Mpesa',
  PAYMENT_PROVIDERS = 'Payment Providers',
  PAYMENT_METHODS = 'Payment Methods',

  // Misc
  FEATURE_FLAGS = 'Feature Flags',
  QUEUE = 'Queue',
  COMMON_UPLOADS = 'Common Uploads',

  // Legacy / existing
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
