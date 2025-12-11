import { Exclude } from 'class-transformer';
import { RefreshToken } from 'src/auth/entities/refresh-token.entity';
import {
  Entity,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  BeforeUpdate,
  BeforeInsert,
  PrimaryGeneratedColumn,
  Index,
  ManyToOne,
  JoinColumn,
  OneToOne,
} from 'typeorm';
import {
  hashPassword as hashWithArgon,
  isArgon2Hash,
} from 'src/common/utils/password.util';
import { Role } from 'src/auth/entities/role.entity';
import { CacheKey } from 'src/auth/entities/cache-key.entity';
import { UserAuthProvider } from 'src/auth/entities/user-auth-provider.entity';
import { CustomerProfile } from './customer-profile.entity';
import { AdminProfile } from './admin-profile.entity';
import { AuthProviderType, MfaChannel, UserStatus } from '../enums';

@Entity('users')
@Index(['email', 'phone'])
@Index('idx_users_status', ['status'])
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'first_name', nullable: true })
  firstName?: string;

  @Column({ name: 'last_name', nullable: true })
  lastName?: string;

  @Column({ unique: true, nullable: true })
  email: string;

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
    length: 32,
    default: AuthProviderType.LOCAL,
  })
  authProvider: AuthProviderType;

  @Column({
    name: 'status',
    type: 'varchar',
    length: 32,
    default: UserStatus.ACTIVE,
  })
  status: UserStatus;

  @Column({ name: 'status_reason', type: 'text', nullable: true })
  statusReason?: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date;

  @Column({
    name: 'last_password_changed_at',
    type: 'timestamp',
    nullable: true,
  })
  lastPasswordChangedAt?: Date;

  @Column({ default: false })
  twoFactorEnabled: boolean;

  @Column({
    name: 'mfa_channel',
    type: 'varchar',
    length: 16,
    default: MfaChannel.EMAIL,
  })
  mfaChannel: MfaChannel;

  @Column({
    name: 'role_id',
    type: 'uuid',
    nullable: true,
  })
  roleId: string;

  @ManyToOne(() => Role, (role) => role.users, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'role_id' })
  role: Role;

  @Column({
    name: 'profile_preferences',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  profilePreferences: Record<string, unknown>;

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshTokens: RefreshToken[];

  @OneToMany(() => CacheKey, (cacheKey) => cacheKey.user)
  cacheKeys: CacheKey[];

  @OneToMany(() => UserAuthProvider, (provider) => provider.user, {
    cascade: true,
  })
  authProviders: UserAuthProvider[];

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
  async hashPassword() {
    // Only hash when a plaintext password was provided
    if (
      this.passwordHash &&
      !isArgon2Hash(this.passwordHash)
    ) {
      this.passwordHash = await hashWithArgon(this.passwordHash);
    }
  }

  set password(value: string | undefined) {
    this.passwordHash = value;
  }

  get password(): string | undefined {
    return this.passwordHash;
  }
}
