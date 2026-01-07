import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { PaymentProvider } from '../entities/payment-provider.entity';

type SeedPaymentProvider = {
  code: string;
  name: string;
  description?: string;
  isActive?: boolean;
  configJson?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
};

@Injectable()
export class PaymentProviderSeeder {
  constructor(
    @InjectRepository(PaymentProvider)
    private readonly providerRepo: Repository<PaymentProvider>,
  ) {}

  private normalizeCode(code: string): string {
    return (code || '').trim().toUpperCase();
  }

  private defaults(): SeedPaymentProvider[] {
    return [
      {
        code: 'SAFARICOM',
        name: 'Safaricom',
        description: 'Safaricom PLC (Kenya) payment provider',
        isActive: true,
        metadata: { seededBy: 'PaymentProviderSeeder', seedKey: 'safaricom' },
      },
      {
        code: 'OFFLINE',
        name: 'Offline/Manual',
        description: 'Cash or manual settlement provider',
        isActive: true,
        metadata: { seededBy: 'PaymentProviderSeeder', seedKey: 'offline' },
      },
      {
        code: 'CARD',
        name: 'Card Gateway',
        description: 'Generic card payment provider',
        isActive: true,
        metadata: { seededBy: 'PaymentProviderSeeder', seedKey: 'card' },
      },
    ];
  }

  private async upsert(provider: SeedPaymentProvider): Promise<void> {
    const code = this.normalizeCode(provider.code);
    if (!code) return;

    const existing = await this.providerRepo.findOne({ where: { code } });
    if (!existing) {
      await this.providerRepo.save(
        this.providerRepo.create({
          code,
          name: provider.name,
          description: provider.description,
          isActive: provider.isActive ?? true,
          configJson: provider.configJson ?? {},
          metadata: provider.metadata ?? {},
        }),
      );
      return;
    }

    existing.name = provider.name;
    existing.description = provider.description;
    existing.isActive = provider.isActive ?? existing.isActive;
    if (typeof provider.configJson !== 'undefined')
      existing.configJson = provider.configJson ?? {};
    if (typeof provider.metadata !== 'undefined')
      existing.metadata = provider.metadata ?? {};

    await this.providerRepo.save(existing);
  }

  async seed(): Promise<void> {
    for (const provider of this.defaults()) {
      await this.upsert(provider);
    }
  }
}
