import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  OneToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from './user.entity';

@Entity('customer_profiles')
export class CustomerProfile {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id', unique: true })
  userId: string;

  @OneToOne(() => User, (user: User) => user.customerProfile, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({ type: 'date', nullable: true })
  dateOfBirth?: Date;

  @Column({ name: 'loyalty_status', default: 'basic' })
  loyaltyStatus: string;

  @Column({ name: 'loyalty_points', type: 'int', default: 0 })
  loyaltyPoints: number;

  @Column({ name: 'marketing_opt_in', default: false })
  marketingOptIn: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
