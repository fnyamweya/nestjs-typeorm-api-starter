import { Column, CreateDateColumn, Entity, Index, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { User } from 'src/user/entities/user.entity';

@Entity('user_auth_providers')
@Index(['provider', 'providerId'], { unique: true })
export class UserAuthProvider {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id' })
  userId: string;

  @Column({ type: 'varchar' })
  provider: string;

  @Column({ type: 'varchar' })
  providerId: string;

  @CreateDateColumn({ name: 'linked_at' })
  linkedAt: Date;

  @ManyToOne(() => User, (user) => user.authProviders, { onDelete: 'CASCADE' })
  user: User;
}
