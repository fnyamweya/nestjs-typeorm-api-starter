import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { PaymentMethod } from '../entities/payment-method.entity';
import { PaymentProvider } from 'src/payment-provider/entities/payment-provider.entity';
import { Channel } from 'src/channels/entities/channel.entity';
import { PaymentMethodChannel } from '../entities/payment-method-channel.entity';
import { Currency } from 'src/catalog/entities/currency.entity';
import { PaymentMethodCurrency } from '../entities/payment-method-currency.entity';
import { CountryConfig } from 'src/country/entities/country-config.entity';
import { PaymentMethodCountryConfig } from '../entities/payment-method-country-config.entity';

type SeedPaymentMethod = {
  code: string;
  providerCode: string;
  name: string;
  description?: string;
  isActive?: boolean;
  channelCodes?: string[];
  countryCodes?: string[];
  currencyCodes?: string[];
  configJson?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
};

@Injectable()
export class PaymentMethodSeeder {
  constructor(
    @InjectRepository(PaymentMethod)
    private readonly methodRepo: Repository<PaymentMethod>,
    @InjectRepository(PaymentProvider)
    private readonly providerRepo: Repository<PaymentProvider>,
    @InjectRepository(Channel)
    private readonly channelRepo: Repository<Channel>,
    @InjectRepository(PaymentMethodChannel)
    private readonly methodChannelRepo: Repository<PaymentMethodChannel>,

    @InjectRepository(Currency)
    private readonly currencyRepo: Repository<Currency>,

    @InjectRepository(PaymentMethodCurrency)
    private readonly methodCurrencyRepo: Repository<PaymentMethodCurrency>,

    @InjectRepository(CountryConfig)
    private readonly countryConfigRepo: Repository<CountryConfig>,

    @InjectRepository(PaymentMethodCountryConfig)
    private readonly methodCountryRepo: Repository<PaymentMethodCountryConfig>,
  ) {}

  private normalizeCode(code: string): string {
    return (code || '').trim().toUpperCase();
  }

  private normalizeCodes(values: string[] | undefined): string[] {
    return Array.from(
      new Set(
        (values ?? [])
          .map((c) =>
            String(c ?? '')
              .trim()
              .toUpperCase(),
          )
          .filter(Boolean),
      ),
    );
  }

  private async setChannels(
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
      throw new Error(
        `Unknown channelCodes for payment method seed: ${missing.join(', ')}`,
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

  private async setCurrencies(
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
      throw new Error(
        `Unknown currencyCodes for payment method seed: ${missing.join(', ')}`,
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

  private async setCountries(
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
      throw new Error(
        `Unknown countryCodes for payment method seed: ${missing.join(', ')}`,
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

  private defaults(): SeedPaymentMethod[] {
    return [
      {
        code: 'MPESA',
        providerCode: 'SAFARICOM',
        name: 'M-Pesa',
        description: 'Safaricom M-Pesa mobile money',
        isActive: true,
        channelCodes: ['WEB', 'MOBILE', 'WHATSAPP'],
        countryCodes: ['KE'],
        currencyCodes: ['KES'],
        // Keep this intentionally flexible: config_json can hold any integration details.
        configJson: {
          kind: 'MPESA',
          integration: { module: 'mpesa' },
          availability: {
            countries: ['KE'],
            currencies: ['KES'],
          },
        },
        metadata: {
          seededBy: 'PaymentMethodSeeder',
          seedKey: 'safaricom-mpesa',
        },
      },
      {
        code: 'CASH',
        providerCode: 'OFFLINE',
        name: 'Cash',
        description: 'Cash payments (in-person or on delivery)',
        isActive: true,
        channelCodes: ['WEB', 'MOBILE', 'WHATSAPP'],
        configJson: {
          kind: 'CASH',
          settlement: 'manual',
        },
        metadata: { seededBy: 'PaymentMethodSeeder', seedKey: 'offline-cash' },
      },
      {
        code: 'BANK_TRANSFER',
        providerCode: 'OFFLINE',
        name: 'Bank Transfer',
        description: 'Manual bank transfer (offline verification)',
        isActive: true,
        channelCodes: ['WEB', 'MOBILE', 'WHATSAPP'],
        configJson: {
          kind: 'BANK_TRANSFER',
          settlement: 'manual',
        },
        metadata: {
          seededBy: 'PaymentMethodSeeder',
          seedKey: 'offline-bank-transfer',
        },
      },
      {
        code: 'CARD',
        providerCode: 'CARD',
        name: 'Card',
        description: 'Card payments (Visa/Mastercard)',
        isActive: true,
        channelCodes: ['WEB', 'MOBILE', 'WHATSAPP'],
        configJson: {
          kind: 'CARD',
        },
        metadata: { seededBy: 'PaymentMethodSeeder', seedKey: 'card-gateway' },
      },
    ];
  }

  private async upsert(method: SeedPaymentMethod): Promise<void> {
    const code = this.normalizeCode(method.code);
    const providerCode = this.normalizeCode(method.providerCode);
    if (!code || !providerCode) return;

    const provider = await this.providerRepo.findOne({
      where: { code: providerCode },
    });
    if (!provider) {
      // Provider seeder should run first; fail loud so missing ordering is obvious.
      throw new Error(`Payment provider not found for code ${providerCode}`);
    }

    const existing = await this.methodRepo.findOne({ where: { code } });
    if (!existing) {
      const created = await this.methodRepo.save(
        this.methodRepo.create({
          code,
          providerId: provider.id,
          name: method.name,
          description: method.description,
          isActive: method.isActive ?? true,
          configJson: method.configJson ?? {},
          metadata: method.metadata ?? {},
        }),
      );

      await this.setChannels(
        created.id,
        this.normalizeCodes(method.channelCodes),
      );
      await this.setCountries(
        created.id,
        this.normalizeCodes(method.countryCodes),
      );
      const currencyCodes = this.normalizeCodes(
        method.currencyCodes ??
          (method.configJson as any)?.availability?.currencies ??
          [],
      );
      await this.setCurrencies(created.id, currencyCodes);
      return;
    }

    existing.providerId = provider.id;
    existing.name = method.name;
    existing.description = method.description;
    existing.isActive = method.isActive ?? existing.isActive;
    if (typeof method.configJson !== 'undefined')
      existing.configJson = method.configJson ?? {};
    if (typeof method.metadata !== 'undefined')
      existing.metadata = method.metadata ?? {};

    const saved = await this.methodRepo.save(existing);
    if (typeof method.channelCodes !== 'undefined') {
      await this.setChannels(
        saved.id,
        this.normalizeCodes(method.channelCodes),
      );
    }
    if (typeof method.countryCodes !== 'undefined') {
      await this.setCountries(
        saved.id,
        this.normalizeCodes(method.countryCodes),
      );
    }
    if (typeof method.configJson !== 'undefined') {
      const currencyCodes = this.normalizeCodes(
        method.currencyCodes ??
          (method.configJson as any)?.availability?.currencies,
      );
      await this.setCurrencies(saved.id, currencyCodes);
    }
  }

  async seed(): Promise<void> {
    for (const method of this.defaults()) {
      await this.upsert(method);
    }
  }
}
