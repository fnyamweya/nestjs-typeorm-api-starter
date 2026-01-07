import { Injectable } from '@nestjs/common';
import { SettingService } from '../../setting/services/setting.service';

@Injectable()
export class ShippingService {
  constructor(private readonly settingService: SettingService) {}

  async calculateShipping(ctx: {
    subtotal: number;
    itemCount?: number;
    currencyCode?: string;
    hasFreeShippingPromo?: boolean;
  }) {
    const s = await this.settingService.getShippingSettings();
    if (!s.shippingEnabled)
      return {
        amount: 0,
        appliedFreeShipping: true,
        meta: { reason: 'shipping_disabled' },
      };

    const freeThreshold = s.freeThreshold || 0;
    const flatFee = s.flatFee || 0;

    const appliedFreeShipping =
      !!ctx.hasFreeShippingPromo || ctx.subtotal >= freeThreshold;
    const amount = appliedFreeShipping ? 0 : flatFee;

    return { amount, appliedFreeShipping, meta: { freeThreshold, flatFee } };
  }
}
