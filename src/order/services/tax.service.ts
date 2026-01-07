import { Injectable } from '@nestjs/common';
import { SettingService } from '../../setting/services/setting.service';

@Injectable()
export class TaxService {
  constructor(private readonly settingService: SettingService) {}

  async calculateTax(ctx: { taxableAmount: number; currencyCode?: string }) {
    const t = await this.settingService.getTaxSettings();
    if (!t.taxEnabled)
      return { amount: 0, rate: 0, meta: { reason: 'tax_disabled' } };

    const rate = (t.taxRate || 0) / 100; // e.g., 16 -> 0.16
    const amount = Math.max(0, ctx.taxableAmount * rate);
    return { amount, rate, meta: { configuredRate: t.taxRate } };
  }
}
