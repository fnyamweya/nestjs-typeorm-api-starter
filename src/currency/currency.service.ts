import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Currency } from '../catalog/entities/currency.entity';
import { normalizeCurrencyCodeOrThrow } from './currency.util';
import { CreateCurrencyDto } from './dto/create-currency.dto';
import { UpdateCurrencyDto } from './dto/update-currency.dto';

@Injectable()
export class CurrencyService {
  private cachedDefault: { code: string; expiresAt: number } | null = null;

  constructor(
    @InjectRepository(Currency)
    private readonly currencyRepo: Repository<Currency>,
  ) {}

  normalizeCode(value: unknown): string {
    return normalizeCurrencyCodeOrThrow(value);
  }

  async list(): Promise<Currency[]> {
    return this.currencyRepo.find({ order: { code: 'ASC' } });
  }

  async getByCode(code: string): Promise<Currency> {
    const normalized = this.normalizeCode(code);
    const row = await this.currencyRepo.findOne({
      where: { code: normalized },
    });
    if (!row) throw new NotFoundException('Currency not found');
    return row;
  }

  async assertExists(code: unknown): Promise<string> {
    const normalized = this.normalizeCode(code);
    const exists = await this.currencyRepo.exist({
      where: { code: normalized },
    });
    if (!exists)
      throw new BadRequestException(`Unknown currency code: ${normalized}`);
    return normalized;
  }

  async getDefaultCurrencyCode(
    preferred: string[] = ['KES', 'USD'],
  ): Promise<string> {
    const now = Date.now();
    if (this.cachedDefault && this.cachedDefault.expiresAt > now)
      return this.cachedDefault.code;

    for (const p of preferred) {
      const normalized = normalizeCurrencyCodeOrThrow(p);
      const exists = await this.currencyRepo.exist({
        where: { code: normalized },
      });
      if (exists) {
        this.cachedDefault = { code: normalized, expiresAt: now + 60_000 };
        return normalized;
      }
    }

    const any = await this.currencyRepo.findOne({
      where: {},
      order: { code: 'ASC' },
    });
    const fallback = any?.code ?? 'USD';
    this.cachedDefault = { code: fallback, expiresAt: now + 60_000 };
    return fallback;
  }

  async upsert(dto: CreateCurrencyDto): Promise<Currency> {
    const code = this.normalizeCode(dto.code);
    const precision = typeof dto.precision === 'number' ? dto.precision : 2;

    const existing = await this.currencyRepo.findOne({ where: { code } });
    if (existing) {
      existing.symbol = dto.symbol ?? existing.symbol;
      existing.precision = precision;
      this.cachedDefault = null;
      return this.currencyRepo.save(existing);
    }

    const created = this.currencyRepo.create({
      code,
      symbol: dto.symbol,
      precision,
    });
    this.cachedDefault = null;
    return this.currencyRepo.save(created);
  }

  async update(code: string, dto: UpdateCurrencyDto): Promise<Currency> {
    const normalized = this.normalizeCode(code);
    const existing = await this.currencyRepo.findOne({
      where: { code: normalized },
    });
    if (!existing) throw new NotFoundException('Currency not found');

    if (typeof dto.symbol !== 'undefined') existing.symbol = dto.symbol;
    if (typeof dto.precision !== 'undefined')
      existing.precision = dto.precision;
    this.cachedDefault = null;
    return this.currencyRepo.save(existing);
  }

  async remove(code: string): Promise<{ deleted: boolean }> {
    const normalized = this.normalizeCode(code);
    const existing = await this.currencyRepo.findOne({
      where: { code: normalized },
    });
    if (!existing) throw new NotFoundException('Currency not found');

    const res = await this.currencyRepo.delete({ code: normalized });
    this.cachedDefault = null;
    return { deleted: (res.affected ?? 0) > 0 };
  }
}
