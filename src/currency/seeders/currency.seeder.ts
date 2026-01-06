import { Injectable } from '@nestjs/common';
import { CurrencyService } from '../currency.service';

type SeedCurrency = {
  code: string;
  symbol?: string;
  precision?: number;
};

@Injectable()
export class CurrencySeeder {
  constructor(private readonly currencyService: CurrencyService) {}

  private defaultCurrencies(): SeedCurrency[] {
    return [
      { code: 'KES', symbol: 'KSh', precision: 2 },
      { code: 'USD', symbol: '$', precision: 2 },
      { code: 'EUR', symbol: '€', precision: 2 },
      { code: 'GBP', symbol: '£', precision: 2 },
      { code: 'UGX', symbol: 'USh', precision: 0 },
      { code: 'TZS', symbol: 'TSh', precision: 2 },
      { code: 'RWF', symbol: 'FRw', precision: 0 },
      { code: 'NGN', symbol: '₦', precision: 2 },
      { code: 'ZAR', symbol: 'R', precision: 2 },
      { code: 'AED', symbol: 'د.إ', precision: 2 },
      { code: 'SAR', symbol: '﷼', precision: 2 },
      { code: 'JPY', symbol: '¥', precision: 0 },
    ];
  }

  async seed(): Promise<void> {
    for (const c of this.defaultCurrencies()) {
      await this.currencyService.upsert({
        code: c.code,
        symbol: c.symbol,
        precision: c.precision,
      });
    }
  }
}
