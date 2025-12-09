import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from 'src/user/entities/user.entity';

export enum ActivityAction {
  LOGIN = 'login',
  LOGOUT = 'logout',
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  CHANGE_PASSWORD = 'change_password',
  FORGOT_PASSWORD_SEND_OTP = 'forgot_password_send_otp',
  RESET_PASSWORD = 'reset_password',
}

@Entity('user_activity_logs')
@Index(['userId', 'createdAt', 'isActivityLog'])
export class UserActivityLog {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column({
    type: 'enum',
    enum: ActivityAction,
  })
  action: ActivityAction;

  @Column({ type: 'text' })
  description: string;

  @Column({ nullable: true })
  resourceType: string;

  @Column({ nullable: true })
  resourceId: string;

  @Column({ nullable: true })
  ipAddress: string;

  @Column({ nullable: true })
  userAgent: string;

  @Column({ nullable: true })
  device: string; // parsed device info

  @Column({ nullable: true })
  browser: string; // parsed browser info

  @Column({ nullable: true })
  os: string; // parsed OS info

  @Column({ nullable: true })
  location: string; // city, country based on IP

  @Column({ default: false })
  isActivityLog: boolean;

  @Column({ type: 'json', nullable: true })
  metadata: Record<string, any>;

  @CreateDateColumn()
  createdAt: Date;
}
