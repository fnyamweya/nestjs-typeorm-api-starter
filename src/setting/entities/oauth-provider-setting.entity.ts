import {
  Entity,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  PrimaryColumn,
  BeforeInsert,
  BeforeUpdate,
  ManyToMany,
  JoinTable,
  Index,
} from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { Role } from 'src/auth/entities/role.entity';

export enum OAuthProvider {
  GOOGLE = 'google',
  APPLE = 'apple',
}

@Entity('oauth_provider_settings')
@Index(['provider'])
@Index(['provider', 'key'], { unique: true })
export class OAuthProviderSetting {
  @PrimaryColumn('uuid')
  id: string;

  @Column({ type: 'varchar' })
  provider: OAuthProvider;

  // URL-safe unique key used to identify the profile in callback URLs.
  // Example: https://<api-host>/auth/<key>/google/callback
  @Column({ type: 'varchar', nullable: true })
  key: string | null;

  @Column({ type: 'varchar' })
  name: string;

  @Column({ type: 'varchar' })
  clientId: string;

  // Encrypted at rest using SettingCryptoService (enc:v1:...)
  @Column({ type: 'text', nullable: true })
  clientSecret: string | null;

  // Apple OAuth fields (used when provider=apple)
  @Column({ type: 'varchar', nullable: true })
  teamId: string | null;

  @Column({ type: 'varchar', nullable: true })
  keyId: string | null;

  // Encrypted at rest using SettingCryptoService (enc:v1:...)
  @Column({ type: 'text', nullable: true })
  privateKey: string | null;

  @Column({ type: 'varchar' })
  callbackUrl: string;

  // Optional: restrict logins by email domain (e.g. ["x.com"]).
  // If empty/undefined, any domain is allowed.
  @Column({ type: 'simple-json', nullable: true })
  allowedDomains?: string[];

  @ManyToMany(() => Role)
  @JoinTable({
    name: 'oauth_provider_setting_roles',
    joinColumn: { name: 'oauth_setting_id', referencedColumnName: 'id' },
    inverseJoinColumn: { name: 'role_id', referencedColumnName: 'id' },
  })
  allowedRoles: Role[];

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
