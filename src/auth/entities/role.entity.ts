import {
  Entity,
  Column,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
  PrimaryColumn,
  BeforeInsert,
  BeforeUpdate,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { Tree, TreeChildren, TreeParent } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { RolePermission } from './role-permission.entity';
import { User } from 'src/user/entities/user.entity';

@Tree('closure-table')
@Entity('roles')
export class Role {
  @PrimaryColumn('uuid')
  id: string;

  @Column({ unique: true })
  name: string;

  @Column({ nullable: true })
  description: string;

  @TreeParent({ onDelete: 'SET NULL' })
  @JoinColumn({ name: 'parent_id' })
  parent?: Role;

  @TreeChildren()
  children?: Role[];

  @OneToMany(() => User, (user) => user.role)
  users: User[];

  @OneToMany(() => RolePermission, (rolePermission) => rolePermission.role)
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
