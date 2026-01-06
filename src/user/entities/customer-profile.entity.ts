import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  OneToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from './user.entity';
import { CustomerTier } from '../../customer-tier/entities/customer-tier.entity';

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

  @Column({ name: 'tier_override_code', type: 'text', nullable: true })
  tierOverrideCode?: string | null;

  @Column({ name: 'tier_id', type: 'uuid', nullable: true })
  tierId?: string | null;

  @ManyToOne(() => CustomerTier, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'tier_id' })
  tier?: CustomerTier | null;

  @Column({ name: 'tier_resolved_code', type: 'text', nullable: true })
  tierResolvedCode?: string | null;

  @Column({ name: 'tier_resolved_at', type: 'timestamptz', nullable: true })
  tierResolvedAt?: Date | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
