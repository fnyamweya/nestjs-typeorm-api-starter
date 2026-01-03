import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ShippingZone } from '../entities/shipping-zone.entity';
import { ShippingZoneLocation } from '../entities/shipping-zone-location.entity';
import { ShippingMethod } from '../entities/shipping-method.entity';
import { ShippingRate } from '../entities/shipping-rate.entity';
import { CreateShippingZoneDto } from '../dto/create-shipping-zone.dto';
import { CreateShippingZoneLocationDto } from '../dto/create-shipping-zone-location.dto';
import { CreateShippingMethodDto } from '../dto/create-shipping-method.dto';
import { CreateShippingRateDto } from '../dto/create-shipping-rate.dto';
import { validateFormula } from '../utils/formula-evaluator';
import { AppCacheService } from 'src/common/cache/app-cache.service';

@Injectable()
export class ShippingAdminService {
  constructor(
    @InjectRepository(ShippingZone)
    private readonly zoneRepo: Repository<ShippingZone>,
    @InjectRepository(ShippingZoneLocation)
    private readonly zoneLocationRepo: Repository<ShippingZoneLocation>,
    @InjectRepository(ShippingMethod)
    private readonly methodRepo: Repository<ShippingMethod>,
    @InjectRepository(ShippingRate)
    private readonly rateRepo: Repository<ShippingRate>,
    private readonly cache: AppCacheService,
  ) {}

  private async invalidateShippingCaches() {
    await this.cache.delByPrefix('shipping:quotes:');
    await this.cache.delByPrefix('shipping:matrix:quotes:');
  }

  // Zones
  async createZone(payload: CreateShippingZoneDto) {
    const zone = this.zoneRepo.create(payload as any);
    const saved = await this.zoneRepo.save(zone);
    await this.invalidateShippingCaches();
    return saved;
  }

  async listZones() {
    return this.zoneRepo.find({ relations: ['locations', 'methods'] });
  }

  async getZone(id: string) {
    const z = await this.zoneRepo.findOne({ where: { id }, relations: ['locations', 'methods'] });
    if (!z) throw new NotFoundException('Shipping zone not found');
    return z;
  }

  async updateZone(id: string, payload: Partial<CreateShippingZoneDto>) {
    await this.zoneRepo.update(id, payload as any);
    await this.invalidateShippingCaches();
    return this.getZone(id);
  }

  async deleteZone(id: string) {
    const res = await this.zoneRepo.delete(id);
    const deleted = (res.affected || 0) > 0;
    if (deleted) await this.invalidateShippingCaches();
    return deleted;
  }

  // Zone locations
  async createZoneLocation(payload: CreateShippingZoneLocationDto) {
    const z = await this.zoneRepo.findOne({ where: { id: payload.zoneId } });
    if (!z) throw new NotFoundException('Shipping zone not found');

    const row = this.zoneLocationRepo.create({
      zoneId: payload.zoneId,
      type: (payload.type as any) ?? 'location',
      locationId: payload.locationId,
    });
    const saved = await this.zoneLocationRepo.save(row);
    await this.invalidateShippingCaches();
    return saved;
  }

  async listZoneLocations(zoneId?: string) {
    if (zoneId) return this.zoneLocationRepo.find({ where: { zoneId } });
    return this.zoneLocationRepo.find();
  }

  async deleteZoneLocation(id: string) {
    const res = await this.zoneLocationRepo.delete(id);
    const deleted = (res.affected || 0) > 0;
    if (deleted) await this.invalidateShippingCaches();
    return deleted;
  }

  // Methods
  async createMethod(payload: CreateShippingMethodDto) {
    const method = this.methodRepo.create(payload as any);
    const saved = await this.methodRepo.save(method);
    await this.invalidateShippingCaches();
    return saved;
  }

  async listMethods(zoneId?: string) {
    if (zoneId) return this.methodRepo.find({ where: { zoneId }, relations: ['rates'] });
    return this.methodRepo.find({ relations: ['rates'] });
  }

  async getMethod(id: string) {
    const m = await this.methodRepo.findOne({ where: { id }, relations: ['rates'] });
    if (!m) throw new NotFoundException('Shipping method not found');
    return m;
  }

  async updateMethod(id: string, payload: Partial<CreateShippingMethodDto>) {
    await this.methodRepo.update(id, payload as any);
    await this.invalidateShippingCaches();
    return this.getMethod(id);
  }

  async deleteMethod(id: string) {
    const res = await this.methodRepo.delete(id);
    const deleted = (res.affected || 0) > 0;
    if (deleted) await this.invalidateShippingCaches();
    return deleted;
  }

  // Rates
  async createRate(payload: CreateShippingRateDto) {
    // validate formula or table_rate metadata as needed
    if (payload.calculationType === 'formula') {
      const formula = (payload.metaJson as any)?.formula || payload.price;
      if (!formula) throw new BadRequestException('Formula rate requires a formula expression in metaJson.formula or a formula in price');
      try {
        validateFormula(String(formula));
      } catch (err: any) {
        throw new BadRequestException(`Invalid formula: ${err?.message || 'unknown error'}`);
      }
    }

    if (payload.calculationType === 'table_rate') {
      const meta = payload.metaJson as any;
      if (!meta || !Array.isArray(meta.tiers) || meta.tiers.length === 0) {
        throw new BadRequestException('table_rate requires metaJson.tiers array with at least one tier');
      }
    }

    const r = this.rateRepo.create(payload as any);
    const saved = await this.rateRepo.save(r);
    await this.invalidateShippingCaches();
    return saved;
  }

  async listRates(methodId?: string) {
    if (methodId) return this.rateRepo.find({ where: { methodId } });
    return this.rateRepo.find();
  }

  async getRate(id: string) {
    const r = await this.rateRepo.findOne({ where: { id } });
    if (!r) throw new NotFoundException('Shipping rate not found');
    return r;
  }

  async updateRate(id: string, payload: Partial<CreateShippingRateDto>) {
    // validate on update too if formula/table_rate provided
    if (payload.calculationType === 'formula' || (payload.metaJson && (payload as any).metaJson?.formula)) {
      const expr = (payload.metaJson as any)?.formula ?? payload.price;
      if (expr) {
        try {
          validateFormula(String(expr));
        } catch (err: any) {
          throw new BadRequestException(`Invalid formula: ${err?.message || 'unknown error'}`);
        }
      }
    }
    if (payload.calculationType === 'table_rate' || (payload.metaJson && (payload as any).metaJson?.tiers)) {
      const meta = (payload as any).metaJson;
      if (!meta || !Array.isArray(meta.tiers) || meta.tiers.length === 0) {
        throw new BadRequestException('table_rate requires metaJson.tiers array with at least one tier');
      }
    }

    await this.rateRepo.update(id, payload as any);
    await this.invalidateShippingCaches();
    return this.getRate(id);
  }

  async deleteRate(id: string) {
    const res = await this.rateRepo.delete(id);
    const deleted = (res.affected || 0) > 0;
    if (deleted) await this.invalidateShippingCaches();
    return deleted;
  }
}
