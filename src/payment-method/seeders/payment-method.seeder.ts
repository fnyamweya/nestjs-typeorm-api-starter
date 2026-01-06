import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { PaymentMethod } from '../entities/payment-method.entity';
import { PaymentProvider } from 'src/payment-provider/entities/payment-provider.entity';

type SeedPaymentMethod = {
  code: string;
  providerCode: string;
  name: string;
  description?: string;
  isActive?: boolean;
  channels?: string[];
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
  ) {}

  private normalizeCode(code: string): string {
    return (code || '').trim().toUpperCase();
  }

  private normalizeChannels(channels: string[] | undefined): string[] {
    return Array.from(
      new Set(
        (channels ?? [])
          .map((c) => String(c ?? '').trim().toUpperCase())
          .filter(Boolean),
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
        channels: ['WEB', 'MOBILE', 'WHATSAPP'],
        // Keep this intentionally flexible: config_json can hold any integration details.
        configJson: {
          kind: 'MPESA',
          integration: { module: 'mpesa' },
          availability: {
            countries: ['KE'],
            currencies: ['KES'],
          },
        },
        metadata: { seededBy: 'PaymentMethodSeeder', seedKey: 'safaricom-mpesa' },
      },
    ];
  }

  private async upsert(method: SeedPaymentMethod): Promise<void> {
    const code = this.normalizeCode(method.code);
    const providerCode = this.normalizeCode(method.providerCode);
    if (!code || !providerCode) return;

    const provider = await this.providerRepo.findOne({ where: { code: providerCode } });
    if (!provider) {
      // Provider seeder should run first; fail loud so missing ordering is obvious.
      throw new Error(`Payment provider not found for code ${providerCode}`);
    }

    const existing = await this.methodRepo.findOne({ where: { code } });
    if (!existing) {
      await this.methodRepo.save(
        this.methodRepo.create({
          code,
          providerId: provider.id,
          name: method.name,
          description: method.description,
          isActive: method.isActive ?? true,
          channels: this.normalizeChannels(method.channels),
          configJson: method.configJson ?? {},
          metadata: method.metadata ?? {},
        }),
      );
      return;
    }

    existing.providerId = provider.id;
    existing.name = method.name;
    existing.description = method.description;
    existing.isActive = method.isActive ?? existing.isActive;
    if (typeof method.channels !== 'undefined') {
      existing.channels = this.normalizeChannels(method.channels);
    }
    if (typeof method.configJson !== 'undefined') existing.configJson = method.configJson ?? {};
    if (typeof method.metadata !== 'undefined') existing.metadata = method.metadata ?? {};

    await this.methodRepo.save(existing);
  }

  async seed(): Promise<void> {
    for (const method of this.defaults()) {
      await this.upsert(method);
    }
  }
}
