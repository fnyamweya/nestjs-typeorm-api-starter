import { Column, Entity, PrimaryColumn } from 'typeorm';

@Entity('currency')
export class Currency {
  @PrimaryColumn({ type: 'char', length: 3 })
  code: string;

  @Column({ type: 'text', nullable: true })
  symbol?: string;

  @Column({ type: 'int', default: 2 })
  precision: number;
}
