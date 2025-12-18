import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ShippingZone } from '../entities/shipping-zone.entity';
import { ShippingMethod } from '../entities/shipping-method.entity';
import { ShippingRate } from '../entities/shipping-rate.entity';
import { CreateShippingZoneDto } from '../dto/create-shipping-zone.dto';
import { CreateShippingMethodDto } from '../dto/create-shipping-method.dto';
import { CreateShippingRateDto } from '../dto/create-shipping-rate.dto';
import { validateFormula } from '../utils/formula-evaluator';

@Injectable()
export class ShippingAdminService {
  constructor(
    @InjectRepository(ShippingZone)
    private readonly zoneRepo: Repository<ShippingZone>,
    @InjectRepository(ShippingMethod)
    private readonly methodRepo: Repository<ShippingMethod>,
    @InjectRepository(ShippingRate)
    private readonly rateRepo: Repository<ShippingRate>,
  ) {}

  // Zones
  async createZone(payload: CreateShippingZoneDto) {
    const zone = this.zoneRepo.create(payload as any);
    return this.zoneRepo.save(zone);
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
    return this.getZone(id);
  }

  async deleteZone(id: string) {
    const res = await this.zoneRepo.delete(id);
    return (res.affected || 0) > 0;
  }

  // Methods
  async createMethod(payload: CreateShippingMethodDto) {
    const method = this.methodRepo.create(payload as any);
    return this.methodRepo.save(method);
  }

  async listMethods(zoneId?: string) {
    if (zoneId) return this.methodRepo.find({ where: { zoneId } });
    return this.methodRepo.find();
  }

  async getMethod(id: string) {
    const m = await this.methodRepo.findOne({ where: { id }, relations: ['rates'] });
    if (!m) throw new NotFoundException('Shipping method not found');
    return m;
  }

  async updateMethod(id: string, payload: Partial<CreateShippingMethodDto>) {
    await this.methodRepo.update(id, payload as any);
    return this.getMethod(id);
  }

  async deleteMethod(id: string) {
    const res = await this.methodRepo.delete(id);
    return (res.affected || 0) > 0;
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
    return this.rateRepo.save(r);
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
    return this.getRate(id);
  }

  async deleteRate(id: string) {
    const res = await this.rateRepo.delete(id);
    return (res.affected || 0) > 0;
  }
}
