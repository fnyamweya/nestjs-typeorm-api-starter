import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ShippingZone } from '../entities/shipping-zone.entity';
import { ShippingZoneLocation } from '../entities/shipping-zone-location.entity';
import { ShippingMethod } from '../entities/shipping-method.entity';
import { ShippingRate } from '../entities/shipping-rate.entity';

@Injectable()
export class ShippingSeeder {
  constructor(
    @InjectRepository(ShippingZone)
    private readonly zoneRepo: Repository<ShippingZone>,
    @InjectRepository(ShippingZoneLocation)
    private readonly locRepo: Repository<ShippingZoneLocation>,
    @InjectRepository(ShippingMethod)
    private readonly methodRepo: Repository<ShippingMethod>,
    @InjectRepository(ShippingRate)
    private readonly rateRepo: Repository<ShippingRate>,
  ) {}

  async seed() {
    // Create a global zone if missing
    let global = await this.zoneRepo.findOne({ where: { code: 'global' } });
    if (!global) {
      global = this.zoneRepo.create({ code: 'global', name: 'Global', description: 'Default fallback zone' });
      await this.zoneRepo.save(global);
    }

    // Add Kenya zone example
    let kenya = await this.zoneRepo.findOne({ where: { code: 'kenya' } });
    if (!kenya) {
      kenya = this.zoneRepo.create({ code: 'kenya', name: 'Kenya', description: 'Kenya shipping zone' });
      await this.zoneRepo.save(kenya);

      await this.locRepo.save(this.locRepo.create({ zoneId: kenya.id, type: 'country', countryCode: 'KE' }));

      const standard = this.methodRepo.create({ zoneId: kenya.id, code: 'standard', displayName: 'Standard Shipping' });
      await this.methodRepo.save(standard);

      // Add flat rate when subtotal < 1000
      await this.rateRepo.save(this.rateRepo.create({ methodId: standard.id, calculationType: 'flat', price: '50.00', priority: 10, metaJson: {} }));
      // Free when subtotal >= 1000
      await this.rateRepo.save(this.rateRepo.create({ methodId: standard.id, calculationType: 'flat', minSubtotal: '1000', price: '0.00', priority: 20 }));

      // weight based express method
      const express = this.methodRepo.create({ zoneId: kenya.id, code: 'express', displayName: 'Express Shipping' });
      await this.methodRepo.save(express);
      await this.rateRepo.save(this.rateRepo.create({ methodId: express.id, calculationType: 'per_weight', price: '0', pricePerUnit: '20.00', minWeight: '0', maxWeight: '5', priority: 5 }));
      await this.rateRepo.save(this.rateRepo.create({ methodId: express.id, calculationType: 'per_weight', price: '0', pricePerUnit: '15.00', minWeight: '5', priority: 1 }));
    }
  }
}
