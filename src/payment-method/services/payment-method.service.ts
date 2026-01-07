import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Brackets, ILike, In, Repository } from 'typeorm';
import { PaymentMethod } from '../entities/payment-method.entity';
import { CreatePaymentMethodDto } from '../dto/create-payment-method.dto';
import { UpdatePaymentMethodDto } from '../dto/update-payment-method.dto';
import { ListPaymentMethodsDto } from '../dto/list-payment-methods.dto';
import { Channel } from '../../channels/entities/channel.entity';
import { PaymentMethodChannel } from '../entities/payment-method-channel.entity';
import { CountryConfig } from '../../country/entities/country-config.entity';
import { PaymentMethodCountryConfig } from '../entities/payment-method-country-config.entity';
import { Currency } from '../../catalog/entities/currency.entity';
import { PaymentMethodCurrency } from '../entities/payment-method-currency.entity';

@Injectable()
export class PaymentMethodService {
  constructor(
    @InjectRepository(PaymentMethod)
    private readonly methodRepo: Repository<PaymentMethod>,

    @InjectRepository(PaymentMethodChannel)
    private readonly methodChannelRepo: Repository<PaymentMethodChannel>,

    @InjectRepository(PaymentMethodCountryConfig)
    private readonly methodCountryRepo: Repository<PaymentMethodCountryConfig>,

    @InjectRepository(PaymentMethodCurrency)
    private readonly methodCurrencyRepo: Repository<PaymentMethodCurrency>,

    @InjectRepository(Channel)
    private readonly channelRepo: Repository<Channel>,

    @InjectRepository(CountryConfig)
    private readonly countryConfigRepo: Repository<CountryConfig>,

    @InjectRepository(Currency)
    private readonly currencyRepo: Repository<Currency>,
  ) {}

  private normalizeCode(code: string): string {
    return (code || '').trim().toUpperCase();
  }

  private normalizeStringCodes(
    values: string[] | undefined,
  ): string[] | undefined {
    if (!values) return undefined;
    return Array.from(
      new Set(
        values
          .map((c) =>
            String(c ?? '')
              .trim()
              .toUpperCase(),
          )
          .filter(Boolean),
      ),
    );
  }

  private normalizeCountryCodes(
    values: string[] | undefined,
  ): string[] | undefined {
    const normalized = this.normalizeStringCodes(values);
    if (!normalized) return undefined;
    const bad = normalized.find((c) => c.length !== 2);
    if (bad)
      throw new BadRequestException('countryCodes must be 2-letter ISO codes');
    return normalized;
  }

  private normalizeCurrencyCodes(
    values: string[] | undefined,
  ): string[] | undefined {
    const normalized = this.normalizeStringCodes(values);
    if (!normalized) return undefined;
    const bad = normalized.find((c) => c.length !== 3);
    if (bad)
      throw new BadRequestException('currencyCodes must be 3-letter ISO codes');
    return normalized;
  }

  private async validateCountryCodesBestEffort(
    countryCodes: string[],
  ): Promise<void> {
    if (countryCodes.length === 0) return;
    const anyConfigured = await this.countryConfigRepo.count();
    if (!anyConfigured) return;

    const existing = await this.countryConfigRepo.find({
      where: { countryCode: In(countryCodes), isActive: true },
      select: { countryCode: true } as any,
    });
    const existingSet = new Set(
      existing.map((c) => String(c.countryCode).toUpperCase()),
    );
    const missing = countryCodes.filter((c) => !existingSet.has(c));
    if (missing.length) {
      throw new BadRequestException(
        `Unknown countryCodes: ${missing.join(', ')}`,
      );
    }
  }

  private async validateCurrencyCodes(currencyCodes: string[]): Promise<void> {
    if (currencyCodes.length === 0) return;
    const existing = await this.currencyRepo.find({
      where: { code: In(currencyCodes) },
      select: { code: true } as any,
    });
    const existingSet = new Set(
      existing.map((c) => String(c.code).toUpperCase()),
    );
    const missing = currencyCodes.filter((c) => !existingSet.has(c));
    if (missing.length) {
      throw new BadRequestException(
        `Unknown currencyCodes: ${missing.join(', ')}`,
      );
    }
  }

  private async setChannelsForMethod(
    methodId: string,
    channelCodes: string[],
  ): Promise<void> {
    await this.methodChannelRepo.delete({ paymentMethodId: methodId } as any);
    if (!channelCodes.length) return;

    const channels = await this.channelRepo.find({
      where: { code: In(channelCodes), isActive: true },
    });
    const foundSet = new Set(channels.map((c) => c.code.toUpperCase()));
    const missing = channelCodes.filter((c) => !foundSet.has(c));
    if (missing.length) {
      throw new BadRequestException(
        `Unknown channelCodes: ${missing.join(', ')}`,
      );
    }

    await this.methodChannelRepo.save(
      channels.map((channel) =>
        this.methodChannelRepo.create({
          paymentMethodId: methodId,
          channelId: channel.id,
          isActive: true,
        }),
      ),
    );
  }

  private async setCountriesForMethod(
    methodId: string,
    countryCodes: string[],
  ): Promise<void> {
    await this.methodCountryRepo.delete({ paymentMethodId: methodId } as any);
    if (!countryCodes.length) return;

    const anyConfigured = await this.countryConfigRepo.count();
    if (!anyConfigured) return;

    const configs = await this.countryConfigRepo.find({
      where: { countryCode: In(countryCodes), isActive: true },
    });
    const foundSet = new Set(
      configs.map((c) => String(c.countryCode).toUpperCase()),
    );
    const missing = countryCodes.filter((c) => !foundSet.has(c));
    if (missing.length) {
      throw new BadRequestException(
        `Unknown countryCodes: ${missing.join(', ')}`,
      );
    }

    await this.methodCountryRepo.save(
      configs.map((countryConfig) =>
        this.methodCountryRepo.create({
          paymentMethodId: methodId,
          countryConfigId: countryConfig.id,
          isActive: true,
        }),
      ),
    );
  }

  private async setCurrenciesForMethod(
    methodId: string,
    currencyCodes: string[],
  ): Promise<void> {
    await this.methodCurrencyRepo.delete({ paymentMethodId: methodId } as any);
    if (!currencyCodes.length) return;

    const currencies = await this.currencyRepo.find({
      where: { code: In(currencyCodes) },
    });
    const foundSet = new Set(
      currencies.map((c) => String(c.code).toUpperCase()),
    );
    const missing = currencyCodes.filter((c) => !foundSet.has(c));
    if (missing.length) {
      throw new BadRequestException(
        `Unknown currencyCodes: ${missing.join(', ')}`,
      );
    }

    await this.methodCurrencyRepo.save(
      currencies.map((currency) =>
        this.methodCurrencyRepo.create({
          paymentMethodId: methodId,
          currencyCode: currency.code,
          isActive: true,
        }),
      ),
    );
  }

  async list(params: ListPaymentMethodsDto): Promise<PaymentMethod[]> {
    const qb = this.methodRepo
      .createQueryBuilder('pm')
      .leftJoinAndSelect('pm.channelLinks', 'pmc')
      .leftJoinAndSelect('pmc.channel', 'channel')
      .leftJoinAndSelect('pm.countryLinks', 'pmcc')
      .leftJoinAndSelect('pmcc.countryConfig', 'country')
      .leftJoinAndSelect('pm.currencyLinks', 'pmcu')
      .leftJoinAndSelect('pmcu.currency', 'currency')
      .orderBy('pm.name', 'ASC');

    if (typeof params.isActive === 'boolean') {
      qb.andWhere('pm.is_active = :isActive', { isActive: params.isActive });
    }
    if (params.providerId) {
      qb.andWhere('pm.provider_id = :providerId', {
        providerId: params.providerId,
      });
    }
    if (params.channel) {
      const channelCode = this.normalizeCode(params.channel);
      if (channelCode) {
        qb.andWhere('channel.code = :channelCode', { channelCode });
        qb.andWhere('pmc.is_active = TRUE');
      }
    }
    if (params.countryCode) {
      const countryCode = this.normalizeCode(params.countryCode);
      if (countryCode) {
        qb.andWhere(
          new Brackets((sub) => {
            sub
              .where(
                `NOT EXISTS (
                  SELECT 1
                  FROM payment_method_country_config x
                  WHERE x.payment_method_id = pm.id
                    AND x.is_active = TRUE
                )`,
              )
              .orWhere(
                `EXISTS (
                  SELECT 1
                  FROM payment_method_country_config x
                  INNER JOIN country_config cc ON cc.id = x.country_config_id
                  WHERE x.payment_method_id = pm.id
                    AND x.is_active = TRUE
                    AND cc.is_active = TRUE
                    AND cc.country_code = :countryCode
                )`,
                { countryCode },
              );
          }),
        );
      }
    }

    if (params.currencyCode) {
      const currencyCode = this.normalizeCode(params.currencyCode);
      if (currencyCode) {
        qb.andWhere(
          new Brackets((sub) => {
            sub
              .where(
                `NOT EXISTS (
                  SELECT 1
                  FROM payment_method_currency x
                  WHERE x.payment_method_id = pm.id
                    AND x.is_active = TRUE
                )`,
              )
              .orWhere(
                `EXISTS (
                  SELECT 1
                  FROM payment_method_currency x
                  INNER JOIN currency cur ON cur.code = x.currency_code
                  WHERE x.payment_method_id = pm.id
                    AND x.is_active = TRUE
                    AND cur.code = :currencyCode
                )`,
                { currencyCode },
              );
          }),
        );
      }
    }

    if (params.q) {
      qb.andWhere(
        new Brackets((sub) => {
          sub
            .where('pm.code ILIKE :q', { q: `%${params.q}%` })
            .orWhere('pm.name ILIKE :q', { q: `%${params.q}%` });
        }),
      );
    }

    return qb.getMany();
  }

  async getById(id: string): Promise<PaymentMethod> {
    const row = await this.methodRepo.findOne({
      where: { id },
      relations: {
        channelLinks: { channel: true },
        countryLinks: { countryConfig: true },
        currencyLinks: { currency: true },
      },
    });
    if (!row) throw new NotFoundException('Payment method not found');
    return row;
  }

  async getByCode(code: string): Promise<PaymentMethod | null> {
    const normalized = this.normalizeCode(code);
    if (!normalized) return null;
    return this.methodRepo.findOne({
      where: { code: normalized },
      relations: {
        channelLinks: { channel: true },
        countryLinks: { countryConfig: true },
        currencyLinks: { currency: true },
      },
    });
  }

  async create(payload: CreatePaymentMethodDto): Promise<PaymentMethod> {
    const code = this.normalizeCode(payload.code);
    if (!code) throw new BadRequestException('code is required');

    const existing = await this.methodRepo.findOne({ where: { code } });
    if (existing)
      throw new BadRequestException('Payment method code already exists');

    const channelCodes =
      this.normalizeStringCodes(payload.channelCodes ?? payload.channels) ?? [];
    const countryCodes = this.normalizeCountryCodes(payload.countryCodes) ?? [];
    const currencyCodes =
      this.normalizeCurrencyCodes(payload.currencyCodes) ?? [];
    await this.validateCountryCodesBestEffort(countryCodes);
    await this.validateCurrencyCodes(currencyCodes);

    const entity = this.methodRepo.create({
      code,
      providerId: payload.providerId,
      name: payload.name,
      description: payload.description,
      isActive: payload.isActive ?? true,
      configJson: payload.configJson ?? {},
      metadata: payload.metadata ?? {},
    });

    const saved = await this.methodRepo.save(entity);
    await this.setChannelsForMethod(saved.id, channelCodes);
    await this.setCountriesForMethod(saved.id, countryCodes);
    await this.setCurrenciesForMethod(saved.id, currencyCodes);
    return this.getById(saved.id);
  }

  async update(
    id: string,
    payload: UpdatePaymentMethodDto,
  ): Promise<PaymentMethod> {
    const existing = await this.methodRepo.findOne({ where: { id } });
    if (!existing) throw new NotFoundException('Payment method not found');

    if (typeof payload.code !== 'undefined') {
      const code = this.normalizeCode(payload.code);
      if (!code) throw new BadRequestException('code is invalid');
      const conflict = await this.methodRepo.findOne({ where: { code } });
      if (conflict && conflict.id !== existing.id) {
        throw new BadRequestException('Payment method code already exists');
      }
      existing.code = code;
    }

    if (typeof payload.providerId !== 'undefined')
      existing.providerId = payload.providerId;
    if (typeof payload.name !== 'undefined') existing.name = payload.name;
    if (typeof payload.description !== 'undefined')
      existing.description = payload.description;
    if (typeof payload.isActive !== 'undefined')
      existing.isActive = payload.isActive;
    if (typeof payload.countryCodes !== 'undefined') {
      const normalized = this.normalizeCountryCodes(payload.countryCodes) ?? [];
      await this.validateCountryCodesBestEffort(normalized);
      await this.setCountriesForMethod(existing.id, normalized);
    }
    if (typeof payload.currencyCodes !== 'undefined') {
      const normalized =
        this.normalizeCurrencyCodes(payload.currencyCodes) ?? [];
      await this.validateCurrencyCodes(normalized);
      await this.setCurrenciesForMethod(existing.id, normalized);
    }
    if (typeof payload.configJson !== 'undefined')
      existing.configJson = payload.configJson ?? {};
    if (typeof payload.metadata !== 'undefined')
      existing.metadata = payload.metadata ?? {};

    const saved = await this.methodRepo.save(existing);

    if (
      typeof payload.channelCodes !== 'undefined' ||
      typeof payload.channels !== 'undefined'
    ) {
      const channelCodes =
        this.normalizeStringCodes(payload.channelCodes ?? payload.channels) ??
        [];
      await this.setChannelsForMethod(saved.id, channelCodes);
    }

    return this.getById(saved.id);
  }

  async delete(id: string): Promise<{ deleted: boolean }> {
    const existing = await this.methodRepo.findOne({ where: { id } });
    if (!existing) throw new NotFoundException('Payment method not found');

    const res = await this.methodRepo.delete(id);
    return { deleted: (res.affected || 0) > 0 };
  }
}
