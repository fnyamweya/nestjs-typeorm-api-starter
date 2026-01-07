import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Order } from 'src/order/entities/order.entity';

export enum MpesaTransactionType {
  C2B = 'c2b',
  B2C = 'b2c',
  B2B = 'b2b',
}

export enum MpesaTransactionStatus {
  PENDING = 'pending',
  SUCCESS = 'success',
  FAILED = 'failed',
  TIMEOUT = 'timeout',
  VALIDATION_RECEIVED = 'validation_received',
  CONFIRMATION_RECEIVED = 'confirmation_received',
}

@Entity('mpesa_transaction')
export class MpesaTransaction {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'order_id', type: 'uuid', nullable: true })
  @Index('idx_mpesa_tx_order_id')
  orderId?: string;

  @ManyToOne(() => Order, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'order_id' })
  order?: Order;

  @Column({ name: 'type', type: 'text' })
  @Index('idx_mpesa_tx_type')
  type: MpesaTransactionType;

  @Column({ name: 'status', type: 'text' })
  @Index('idx_mpesa_tx_status')
  status: MpesaTransactionStatus;

  @Column({ name: 'originator_conversation_id', type: 'text', nullable: true })
  @Index('idx_mpesa_tx_originator_conversation_id')
  originatorConversationId?: string;

  @Column({ name: 'conversation_id', type: 'text', nullable: true })
  @Index('idx_mpesa_tx_conversation_id')
  conversationId?: string;

  @Column({ name: 'transaction_id', type: 'text', nullable: true })
  @Index('idx_mpesa_tx_transaction_id')
  transactionId?: string;

  @Column({ name: 'result_code', type: 'int', nullable: true })
  resultCode?: number;

  @Column({ name: 'result_desc', type: 'text', nullable: true })
  resultDesc?: string;

  @Column({
    name: 'amount',
    type: 'numeric',
    precision: 18,
    scale: 4,
    nullable: true,
  })
  amount?: string;

  @Column({ name: 'msisdn', type: 'text', nullable: true })
  msisdn?: string;

  @Column({ name: 'bill_ref_number', type: 'text', nullable: true })
  billRefNumber?: string;

  @Column({ name: 'account_reference', type: 'text', nullable: true })
  accountReference?: string;

  @Column({ name: 'party_a', type: 'text', nullable: true })
  partyA?: string;

  @Column({ name: 'party_b', type: 'text', nullable: true })
  partyB?: string;

  @Column({ name: 'remarks', type: 'text', nullable: true })
  remarks?: string;

  @Column({
    name: 'raw_request_json',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  rawRequestJson: Record<string, unknown>;

  @Column({
    name: 'raw_response_json',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  rawResponseJson: Record<string, unknown>;

  @Column({
    name: 'raw_callback_json',
    type: 'jsonb',
    default: () => "'{}'::jsonb",
  })
  rawCallbackJson: Record<string, unknown>;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
