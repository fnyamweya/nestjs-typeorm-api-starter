import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { EntityManager, Repository } from 'typeorm';
import { AccountingAccountType, AccountingSourceType } from './accounting.types';
import { ACCOUNT_CODES } from './accounting.constants';
import { AccountingAccount } from './entities/accounting-account.entity';
import { JournalEntry } from './entities/journal-entry.entity';
import { JournalEntryLine } from './entities/journal-entry-line.entity';

function normalizeCode(code: string): string {
  return String(code || '')
    .trim()
    .toUpperCase();
}

function toMoneyString(amount: number): string {
  if (!Number.isFinite(amount)) throw new BadRequestException('Invalid amount');
  return amount.toFixed(4);
}

export type PostJournalEntryLineInput = {
  accountCode: string;
  debit?: number;
  credit?: number;
  memo?: string;
  metaJson?: Record<string, unknown>;
};

export type PostJournalEntryInput = {
  idempotencyKey: string;
  currency: string;
  sourceType?: AccountingSourceType | string;
  sourceId?: string;
  postedAt?: Date;
  memo?: string;
  metaJson?: Record<string, unknown>;
  lines: PostJournalEntryLineInput[];
};

@Injectable()
export class AccountingService {
  constructor(
    @InjectRepository(AccountingAccount)
    private readonly accountRepo: Repository<AccountingAccount>,
    @InjectRepository(JournalEntry)
    private readonly entryRepo: Repository<JournalEntry>,
    @InjectRepository(JournalEntryLine)
    private readonly lineRepo: Repository<JournalEntryLine>,
  ) {}

  async ensureDefaultAccounts(
    manager?: EntityManager,
  ): Promise<Record<string, AccountingAccount>> {
    const repo = manager ? manager.getRepository(AccountingAccount) : this.accountRepo;

    const defaults: Array<
      Pick<AccountingAccount, 'code' | 'name' | 'type' | 'isActive' | 'metaJson'>
    > = [
      {
        code: ACCOUNT_CODES.CASH_CLEARING,
        name: 'Cash / Payment Processor Clearing',
        type: AccountingAccountType.ASSET,
        isActive: true,
        metaJson: {},
      },
      {
        code: ACCOUNT_CODES.ORDER_LIABILITY,
        name: 'Order Liability (Unrecognized Revenue)',
        type: AccountingAccountType.LIABILITY,
        isActive: true,
        metaJson: {},
      },
      {
        code: ACCOUNT_CODES.SALES_REVENUE,
        name: 'Sales Revenue',
        type: AccountingAccountType.REVENUE,
        isActive: true,
        metaJson: {},
      },
      {
        code: ACCOUNT_CODES.ADJUSTMENTS,
        name: 'Payment Adjustments',
        type: AccountingAccountType.EXPENSE,
        isActive: true,
        metaJson: {},
      },
    ];

    await repo
      .createQueryBuilder()
      .insert()
      .into(AccountingAccount)
      .values(defaults as any)
      .orIgnore()
      .execute();

    const found = await repo.find({ where: defaults.map((d) => ({ code: d.code })) as any });
    const byCode: Record<string, AccountingAccount> = {};
    for (const a of found) byCode[a.code] = a;
    return byCode;
  }

  async listAccounts(opts?: { includeInactive?: boolean }): Promise<AccountingAccount[]> {
    const includeInactive = Boolean(opts?.includeInactive);
    return this.accountRepo.find({
      where: includeInactive ? {} : ({ isActive: true } as any),
      order: { code: 'ASC' as any },
    });
  }

  async exportChartOfAccountsCsv(opts?: { includeInactive?: boolean }): Promise<string> {
    const accounts = await this.listAccounts(opts);
    const header = ['code', 'name', 'type', 'isActive'].join(',');
    const rows = accounts.map((a) =>
      [a.code, a.name, a.type, String(a.isActive)].map(csvEscape).join(','),
    );
    return [header, ...rows].join('\n') + '\n';
  }

  async listJournalEntries(opts: {
    page?: number;
    limit?: number;
    from?: Date;
    to?: Date;
    sourceType?: string;
    sourceId?: string;
    idempotencyKey?: string;
    accountCode?: string;
  }): Promise<{ data: JournalEntry[]; total: number; page: number; limit: number }> {
    const page = Math.max(1, Number(opts.page ?? 1) || 1);
    const limit = Math.min(200, Math.max(1, Number(opts.limit ?? 50) || 50));
    const skip = (page - 1) * limit;

    const qb = this.entryRepo
      .createQueryBuilder('je')
      .leftJoinAndSelect('je.lines', 'jel')
      .leftJoinAndSelect('jel.account', 'acc')
      .orderBy('je.posted_at', 'DESC')
      .addOrderBy('je.created_at', 'DESC')
      .skip(skip)
      .take(limit);

    if (opts.from) qb.andWhere('je.posted_at >= :from', { from: opts.from });
    if (opts.to) qb.andWhere('je.posted_at <= :to', { to: opts.to });
    if (opts.sourceType)
      qb.andWhere('je.source_type = :sourceType', { sourceType: opts.sourceType });
    if (opts.sourceId)
      qb.andWhere('je.source_id = :sourceId', { sourceId: opts.sourceId });
    if (opts.idempotencyKey)
      qb.andWhere('je.idempotency_key = :idk', { idk: opts.idempotencyKey });

    if (opts.accountCode) {
      qb.andWhere('acc.code = :accountCode', { accountCode: opts.accountCode });
    }

    const [data, total] = await qb.getManyAndCount();
    return { data, total, page, limit };
  }

  async getTrialBalance(opts: {
    asOf: Date;
  }): Promise<
    Array<{
      accountCode: string;
      accountName: string;
      accountType: string;
      debitTotal: string;
      creditTotal: string;
      net: string;
    }>
  > {
    const asOf = opts.asOf;

    const rows = await this.lineRepo
      .createQueryBuilder('l')
      .innerJoin('l.entry', 'e')
      .innerJoin('l.account', 'a')
      .select('a.code', 'accountCode')
      .addSelect('a.name', 'accountName')
      .addSelect('a.type', 'accountType')
      .addSelect('COALESCE(SUM(l.debit), 0)', 'debitTotal')
      .addSelect('COALESCE(SUM(l.credit), 0)', 'creditTotal')
      .where('e.posted_at <= :asOf', { asOf })
      .groupBy('a.code')
      .addGroupBy('a.name')
      .addGroupBy('a.type')
      .orderBy('a.code', 'ASC')
      .getRawMany<{
        accountCode: string;
        accountName: string;
        accountType: string;
        debitTotal: string;
        creditTotal: string;
      }>();

    return rows.map((r) => {
      const net = (Number(r.debitTotal) - Number(r.creditTotal)).toFixed(4);
      return { ...r, net };
    });
  }

  async getPeriodicRevenue(opts: {
    from: Date;
    to: Date;
    bucket: 'day' | 'month';
  }): Promise<Array<{ period: string; revenue: string }>> {
    const bucket = opts.bucket;
    const fmt = bucket === 'month' ? 'YYYY-MM' : 'YYYY-MM-DD';

    // Revenue = credits - debits on SALES_REVENUE
    const rows = await this.lineRepo
      .createQueryBuilder('l')
      .innerJoin('l.entry', 'e')
      .innerJoin('l.account', 'a')
      .select(`to_char(e.posted_at, '${fmt}')`, 'period')
      .addSelect('COALESCE(SUM(l.credit) - SUM(l.debit), 0)', 'revenue')
      .where('a.code = :code', { code: ACCOUNT_CODES.SALES_REVENUE })
      .andWhere('e.posted_at >= :from AND e.posted_at <= :to', {
        from: opts.from,
        to: opts.to,
      })
      .groupBy('period')
      .orderBy('period', 'ASC')
      .getRawMany<{ period: string; revenue: string }>();

    return rows.map((r) => ({ period: r.period, revenue: Number(r.revenue).toFixed(4) }));
  }

  async getPeriodicCashReceipts(opts: {
    from: Date;
    to: Date;
    bucket: 'day' | 'month';
  }): Promise<Array<{ period: string; netCashInflow: string }>> {
    const bucket = opts.bucket;
    const fmt = bucket === 'month' ? 'YYYY-MM' : 'YYYY-MM-DD';

    // Net inflow on CASH_CLEARING = debits - credits
    const rows = await this.lineRepo
      .createQueryBuilder('l')
      .innerJoin('l.entry', 'e')
      .innerJoin('l.account', 'a')
      .select(`to_char(e.posted_at, '${fmt}')`, 'period')
      .addSelect('COALESCE(SUM(l.debit) - SUM(l.credit), 0)', 'netCashInflow')
      .where('a.code = :code', { code: ACCOUNT_CODES.CASH_CLEARING })
      .andWhere('e.posted_at >= :from AND e.posted_at <= :to', {
        from: opts.from,
        to: opts.to,
      })
      .groupBy('period')
      .orderBy('period', 'ASC')
      .getRawMany<{ period: string; netCashInflow: string }>();

    return rows.map((r) => ({ period: r.period, netCashInflow: Number(r.netCashInflow).toFixed(4) }));
  }

  async postEntry(manager: EntityManager, input: PostJournalEntryInput): Promise<JournalEntry> {
    const idempotencyKey = String(input.idempotencyKey || '').trim();
    if (!idempotencyKey) throw new BadRequestException('idempotencyKey is required');

    const currency = normalizeCode(input.currency);
    if (!currency) throw new BadRequestException('currency is required');

    const entryRepo = manager.getRepository(JournalEntry);
    const lineRepo = manager.getRepository(JournalEntryLine);

    const existing = await entryRepo.findOne({ where: { idempotencyKey } });
    if (existing) {
      return entryRepo.findOneOrFail({ where: { id: existing.id }, relations: { lines: true } as any });
    }

    if (!input.lines?.length) throw new BadRequestException('lines are required');

    const totalDebit = input.lines.reduce((acc, l) => acc + Number(l.debit ?? 0), 0);
    const totalCredit = input.lines.reduce((acc, l) => acc + Number(l.credit ?? 0), 0);
    if (Number(totalDebit.toFixed(4)) !== Number(totalCredit.toFixed(4))) {
      throw new BadRequestException('Journal entry must be balanced (total debit = total credit)');
    }

    const accounts = await this.ensureDefaultAccounts(manager);

    const entry = entryRepo.create({
      idempotencyKey,
      currencyCode: currency,
      sourceType: input.sourceType,
      sourceId: input.sourceId,
      postedAt: input.postedAt ?? new Date(),
      memo: input.memo,
      metaJson: input.metaJson ?? {},
    });

    const savedEntry = await entryRepo.save(entry);

    const lines: JournalEntryLine[] = [];
    for (const l of input.lines) {
      const accountCode = String(l.accountCode || '').trim();
      const account = accounts[accountCode];
      if (!account) {
        throw new BadRequestException(`Unknown accounting account: ${accountCode}`);
      }

      const debit = Number(l.debit ?? 0);
      const credit = Number(l.credit ?? 0);

      if (!Number.isFinite(debit) || !Number.isFinite(credit)) {
        throw new BadRequestException('Journal line amounts must be numbers');
      }
      if (debit < 0 || credit < 0) {
        throw new BadRequestException('Journal line debit/credit must be >= 0');
      }
      if ((debit > 0 && credit > 0) || (debit === 0 && credit === 0)) {
        throw new BadRequestException('Journal line must have either debit or credit (not both)');
      }

      lines.push(
        lineRepo.create({
          entryId: savedEntry.id,
          accountId: account.id,
          debit: toMoneyString(debit),
          credit: toMoneyString(credit),
          currencyCode: currency,
          memo: l.memo,
          metaJson: l.metaJson ?? {},
        }),
      );
    }

    await lineRepo.save(lines);

    return entryRepo.findOneOrFail({
      where: { id: savedEntry.id },
      relations: { lines: true } as any,
    });
  }

  /**
   * Posts a balanced entry for an order payment.
   *
   * Policy (minimal + extensible):
   * - CAPTURE: Dr CashClearing, Cr OrderLiability
   * - REFUND/REVERSAL: Dr OrderLiability, Cr CashClearing
   * - ADJUSTMENT:
   *   - INTERNAL/MANUAL => Dr/Cr OrderLiability vs Adjustments (no cash)
   *   - otherwise behaves like CAPTURE/REFUND based on sign
   */
  async postForOrderPayment(
    manager: EntityManager,
    input: {
      paymentId: string;
      orderId: string;
      type: string;
      provider: string;
      method: string;
      amount: number;
      currency: string;
      postedAt?: Date;
    },
  ): Promise<JournalEntry> {
    const idempotencyKey = `order_payment:${input.paymentId}`;

    const type = String(input.type || '').trim().toUpperCase();
    const provider = String(input.provider || '').trim().toUpperCase();
    const method = String(input.method || '').trim().toUpperCase();

    // Amount here is the request amount, always positive except ADJUSTMENT can be negative.
    const amountAbs = Math.abs(Number(input.amount));
    if (!Number.isFinite(amountAbs) || amountAbs === 0) {
      throw new BadRequestException('Invalid payment amount for posting');
    }

    const cash = ACCOUNT_CODES.CASH_CLEARING;
    const liability = ACCOUNT_CODES.ORDER_LIABILITY;
    const adjustments = ACCOUNT_CODES.ADJUSTMENTS;

    const isInternalAdjustment = type === 'ADJUSTMENT' && provider === 'INTERNAL' && method === 'MANUAL';

    // Decide direction
    // - CAPTURE => cash debit
    // - REFUND/REVERSAL => cash credit
    // - ADJUSTMENT => based on sign
    let cashDebit = 0;
    let cashCredit = 0;
    let liabDebit = 0;
    let liabCredit = 0;

    if (type === 'CAPTURE') {
      cashDebit = amountAbs;
      liabCredit = amountAbs;
    } else if (type === 'REFUND' || type === 'REVERSAL') {
      liabDebit = amountAbs;
      cashCredit = amountAbs;
    } else if (type === 'ADJUSTMENT') {
      const signed = Number(input.amount);
      if (!Number.isFinite(signed) || signed === 0) {
        throw new BadRequestException('Invalid adjustment amount for posting');
      }
      if (signed > 0) {
        cashDebit = amountAbs;
        liabCredit = amountAbs;
      } else {
        liabDebit = amountAbs;
        cashCredit = amountAbs;
      }
    } else {
      throw new BadRequestException(`Unsupported payment type for posting: ${type}`);
    }

    if (isInternalAdjustment) {
      // Re-route cash side into adjustments account.
      // Positive: Dr Adjustments, Cr OrderLiability
      // Negative: Dr OrderLiability, Cr Adjustments
      if (cashDebit > 0) {
        cashDebit = 0;
        return this.postEntry(manager, {
          idempotencyKey,
          currency: input.currency,
          sourceType: AccountingSourceType.ORDER_PAYMENT,
          sourceId: input.paymentId,
          postedAt: input.postedAt,
          memo: `Order payment ${type} (${provider}/${method})`,
          metaJson: { orderId: input.orderId },
          lines: [
            { accountCode: adjustments, debit: amountAbs },
            { accountCode: liability, credit: amountAbs },
          ],
        });
      }

      if (cashCredit > 0) {
        cashCredit = 0;
        return this.postEntry(manager, {
          idempotencyKey,
          currency: input.currency,
          sourceType: AccountingSourceType.ORDER_PAYMENT,
          sourceId: input.paymentId,
          postedAt: input.postedAt,
          memo: `Order payment ${type} (${provider}/${method})`,
          metaJson: { orderId: input.orderId },
          lines: [
            { accountCode: liability, debit: amountAbs },
            { accountCode: adjustments, credit: amountAbs },
          ],
        });
      }
    }

    return this.postEntry(manager, {
      idempotencyKey,
      currency: input.currency,
      sourceType: AccountingSourceType.ORDER_PAYMENT,
      sourceId: input.paymentId,
      postedAt: input.postedAt,
      memo: `Order payment ${type} (${provider}/${method})`,
      metaJson: { orderId: input.orderId },
      lines: [
        cashDebit > 0
          ? { accountCode: cash, debit: cashDebit }
          : { accountCode: cash, credit: cashCredit },
        liabDebit > 0
          ? { accountCode: liability, debit: liabDebit }
          : { accountCode: liability, credit: liabCredit },
      ],
    });
  }

  async postRevenueRecognitionForFulfillment(
    manager: EntityManager,
    input: {
      fulfillmentId: string;
      orderId: string;
      currency: string;
      amount: number;
      postedAt?: Date;
    },
  ): Promise<JournalEntry> {
    const amount = Number(input.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      throw new BadRequestException('Invalid revenue recognition amount');
    }

    return this.postEntry(manager, {
      idempotencyKey: `revenue_recognition:fulfillment:${input.fulfillmentId}`,
      currency: input.currency,
      sourceType: 'ORDER_FULFILLMENT',
      sourceId: input.fulfillmentId,
      postedAt: input.postedAt,
      memo: 'Recognize revenue for delivered fulfillment',
      metaJson: { orderId: input.orderId, fulfillmentId: input.fulfillmentId },
      lines: [
        { accountCode: ACCOUNT_CODES.ORDER_LIABILITY, debit: amount },
        { accountCode: ACCOUNT_CODES.SALES_REVENUE, credit: amount },
      ],
    });
  }
}

function csvEscape(value: unknown): string {
  const s = String(value ?? '');
  if (s.includes('"') || s.includes(',') || s.includes('\n') || s.includes('\r')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}
