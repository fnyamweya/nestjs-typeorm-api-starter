import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ShippingZone } from '../entities/shipping-zone.entity';
import { ShippingZoneLocation } from '../entities/shipping-zone-location.entity';
import { ShippingMethod } from '../entities/shipping-method.entity';
import { ShippingRate } from '../entities/shipping-rate.entity';
import { ShippingZoneMethod } from '../entities/shipping-zone-method.entity';
import {
  Location,
  LocationType,
} from '../../location/entities/location.entity';

@Injectable()
export class ShippingSeeder {
  constructor(
    @InjectRepository(ShippingZone)
    private readonly zoneRepo: Repository<ShippingZone>,
    @InjectRepository(ShippingZoneLocation)
    private readonly locRepo: Repository<ShippingZoneLocation>,
    @InjectRepository(ShippingMethod)
    private readonly methodRepo: Repository<ShippingMethod>,
    @InjectRepository(ShippingZoneMethod)
    private readonly zoneMethodRepo: Repository<ShippingZoneMethod>,
    @InjectRepository(ShippingRate)
    private readonly rateRepo: Repository<ShippingRate>,
    @InjectRepository(Location)
    private readonly locationRepo: Repository<Location>,
  ) {}

  async seed() {
    // Create a global zone if missing
    let global = await this.zoneRepo.findOne({ where: { code: 'global' } });
    if (!global) {
      global = this.zoneRepo.create({
        code: 'global',
        name: 'Global',
        description: 'Default fallback zone',
      });
      await this.zoneRepo.save(global);
    }

    // Add Kenya zone example
    let kenya = await this.zoneRepo.findOne({ where: { code: 'kenya' } });
    if (!kenya) {
      kenya = this.zoneRepo.create({
        code: 'kenya',
        name: 'Kenya',
        description: 'Kenya shipping zone',
      });
      await this.zoneRepo.save(kenya);
    }

    // Ensure Kenya zone has a locationId mapping (required for the locationId-only matcher)
    const kenyaCountry = await this.locationRepo.findOne({
      where: { type: LocationType.COUNTRY, countryCode: 'KE' },
    });
    if (kenya && kenyaCountry) {
      const existing = await this.locRepo.findOne({
        where: { zoneId: kenya.id, locationId: kenyaCountry.id },
      });
      if (!existing) {
        await this.locRepo.save(
          this.locRepo.create({
            zoneId: kenya.id,
            type: 'location',
            locationId: kenyaCountry.id,
            countryCode: 'KE',
          }),
        );
      }
    }

    // Seed basic methods/rates if missing
    if (kenya) {
      let standard = await this.methodRepo.findOne({
        where: { code: 'standard' },
      });
      if (!standard) {
        standard = this.methodRepo.create({
          code: 'standard',
          displayName: 'Standard Shipping',
          isActive: true,
        });
        await this.methodRepo.save(standard);
      }

      const standardAttach = await this.zoneMethodRepo.findOne({
        where: { zoneId: kenya.id, shippingMethodId: standard.id },
      });
      if (!standardAttach) {
        await this.zoneMethodRepo.save(
          this.zoneMethodRepo.create({
            zoneId: kenya.id,
            shippingMethodId: standard.id,
            isActive: true,
          }),
        );
      }

      const standardRates = await this.rateRepo.find({
        where: { methodId: standard.id },
      });
      if (!standardRates.length) {
        // Add flat rate when subtotal < 1000
        await this.rateRepo.save(
          this.rateRepo.create({
            methodId: standard.id,
            calculationType: 'flat',
            price: '50.00',
            priority: 10,
            metaJson: {},
          }),
        );
        // Free when subtotal >= 1000
        await this.rateRepo.save(
          this.rateRepo.create({
            methodId: standard.id,
            calculationType: 'flat',
            minSubtotal: '1000',
            price: '0.00',
            priority: 20,
          }),
        );
      }

      let express = await this.methodRepo.findOne({
        where: { code: 'express' },
      });
      if (!express) {
        express = this.methodRepo.create({
          code: 'express',
          displayName: 'Express Shipping',
          isActive: true,
        });
        await this.methodRepo.save(express);
      }

      const expressAttach = await this.zoneMethodRepo.findOne({
        where: { zoneId: kenya.id, shippingMethodId: express.id },
      });
      if (!expressAttach) {
        await this.zoneMethodRepo.save(
          this.zoneMethodRepo.create({
            zoneId: kenya.id,
            shippingMethodId: express.id,
            isActive: true,
          }),
        );
      }

      const expressRates = await this.rateRepo.find({
        where: { methodId: express.id },
      });
      if (!expressRates.length) {
        await this.rateRepo.save(
          this.rateRepo.create({
            methodId: express.id,
            calculationType: 'per_weight',
            price: '0',
            pricePerUnit: '20.00',
            minWeight: '0',
            maxWeight: '5',
            priority: 5,
          }),
        );
        await this.rateRepo.save(
          this.rateRepo.create({
            methodId: express.id,
            calculationType: 'per_weight',
            price: '0',
            pricePerUnit: '15.00',
            minWeight: '5',
            priority: 1,
          }),
        );
      }
    }
  }
}
