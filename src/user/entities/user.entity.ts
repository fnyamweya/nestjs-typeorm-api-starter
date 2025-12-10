import { Exclude } from 'class-transformer';
import { RefreshToken } from 'src/auth/entities/refresh-token.entity';
import { v4 as uuidv4 } from 'uuid';
import {
  Entity,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  BeforeUpdate,
  BeforeInsert,
  PrimaryColumn,
  Index,
  ManyToOne,
  JoinColumn,
  OneToOne,
} from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { Role } from 'src/auth/entities/role.entity';
import { CacheKey } from 'src/auth/entities/cache-key.entity';
import { CustomerProfile } from './customer-profile.entity';
import { AdminProfile } from './admin-profile.entity';

@Entity('users')
@Index(['email', 'fullName', 'phone'])
export class User {
  @PrimaryColumn('uuid')
  id: string;

  @Column({ name: 'first_name', nullable: true })
  firstName?: string;

  @Column({ name: 'last_name', nullable: true })
  lastName?: string;

  @Column({ unique: true, nullable: true })
  email: string;

  @Column({ nullable: true })
  fullName: string;

  @Column({ nullable: false, unique: true })
  phone: string;

  @Column({ nullable: true, name: 'password' })
  @Exclude()
  passwordHash?: string;

  @Column({ default: false })
  isBanned: boolean;

  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @Column({ nullable: true })
  profileImageUrl: string;

  @Column({
    name: 'auth_provider',
    type: 'varchar',
    default: 'local',
  })
  authProvider: 'local' | 'google' | 'saml' | 'github' | string;

  @Column({
    name: 'role_type',
    type: 'varchar',
    default: 'customer',
  })
  roleType: 'customer' | 'admin' | 'support' | 'vendor' | string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date;

  @Column({ default: false })
  twoFactorEnabled: boolean;

  @Column({ name: 'mfa_channel', type: 'varchar', default: 'email' })
  mfaChannel: 'email' | 'sms' | string;

  @Column({ nullable: true })
  roleId: string;

  @ManyToOne(() => Role, (role) => role.users, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'roleId' })
  role: Role;

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshTokens: RefreshToken[];

  @OneToMany(() => CacheKey, (cacheKey) => cacheKey.user)
  cacheKeys: CacheKey[];

  @OneToOne(() => CustomerProfile, (profile: CustomerProfile) => profile.user, {
    cascade: true,
  })
  customerProfile?: CustomerProfile;

  @OneToOne(() => AdminProfile, (profile: AdminProfile) => profile.user, {
    cascade: true,
  })
  adminProfile?: AdminProfile;

  @BeforeInsert()
  @BeforeUpdate()
  generateUUID() {
    if (!this.id) {
      this.id = uuidv4();
    }
  }

  @BeforeInsert()
  async hashPassword() {
    // Only hash when a plaintext password was provided
    if (this.passwordHash && !this.passwordHash.startsWith('$2')) {
      const hashedPassword = await bcrypt.hash(
        this.passwordHash,
        Number(process.env.AUTH_PASSWORD_SALT_ROUNDS),
      );
      this.passwordHash = hashedPassword;
    }
  }

  set password(value: string | undefined) {
    this.passwordHash = value;
  }

  get password(): string | undefined {
    return this.passwordHash;
  }
}
