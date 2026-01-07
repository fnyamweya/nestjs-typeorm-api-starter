import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { ShippingZone } from '../entities/shipping-zone.entity';
import { ShippingZoneLocation } from '../entities/shipping-zone-location.entity';
import { ShippingMethod } from '../entities/shipping-method.entity';
import { ShippingRate } from '../entities/shipping-rate.entity';
import { ShippingZoneMethod } from '../entities/shipping-zone-method.entity';
import { ShippingProvider } from '../entities/shipping-provider.entity';
import { CreateShippingZoneDto } from '../dto/create-shipping-zone.dto';
import { CreateShippingZoneLocationDto } from '../dto/create-shipping-zone-location.dto';
import { CreateShippingMethodDto } from '../dto/create-shipping-method.dto';
import { CreateShippingRateDto } from '../dto/create-shipping-rate.dto';
import { validateFormula } from '../utils/formula-evaluator';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { Location } from 'src/location/entities/location.entity';
import { Channel } from 'src/channels/entities/channel.entity';
import { CurrencyService } from 'src/currency/currency.service';

@Injectable()
export class ShippingAdminService {
  constructor(
    @InjectRepository(ShippingZone)
    private readonly zoneRepo: Repository<ShippingZone>,
    @InjectRepository(ShippingZoneLocation)
    private readonly zoneLocationRepo: Repository<ShippingZoneLocation>,
    @InjectRepository(ShippingMethod)
    private readonly methodRepo: Repository<ShippingMethod>,
    @InjectRepository(ShippingZoneMethod)
    private readonly zoneMethodRepo: Repository<ShippingZoneMethod>,
    @InjectRepository(ShippingProvider)
    private readonly providerRepo: Repository<ShippingProvider>,
    @InjectRepository(ShippingRate)
    private readonly rateRepo: Repository<ShippingRate>,
    @InjectRepository(Channel)
    private readonly channelRepo: Repository<Channel>,
    @InjectRepository(Location)
    private readonly locationRepo: Repository<Location>,
    private readonly cache: AppCacheService,
    private readonly currencyService: CurrencyService,
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
    return this.zoneRepo.find({
      relations: ['locations', 'zoneMethods', 'zoneMethods.method'],
    });
  }

  async getZone(id: string) {
    const z = await this.zoneRepo.findOne({
      where: { id },
      relations: ['locations', 'zoneMethods', 'zoneMethods.method'],
    });
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

    const resolvedType = (payload.type as any) ?? 'location';

    // Prefer inferring countryCode from the referenced Location.
    const loc = await this.locationRepo.findOne({
      where: { id: payload.locationId },
      select: { id: true, countryCode: true } as any,
    });

    const resolvedCountryCode =
      (loc?.countryCode ? String(loc.countryCode).toUpperCase() : undefined) ??
      (payload.countryCode ? String(payload.countryCode).toUpperCase() : undefined);

    const row = this.zoneLocationRepo.create({
      zoneId: payload.zoneId,
      type: resolvedType,
      locationId: payload.locationId,
      countryCode: resolvedCountryCode,
    });

    const saved = await this.zoneLocationRepo.save(row);
    const hydrated = await this.zoneLocationRepo.findOne({
      where: { id: saved.id },
      relations: ['location'],
    });
    await this.invalidateShippingCaches();
    return hydrated ?? saved;
  }

  async listZoneLocations(zoneId?: string) {
    if (zoneId)
      return this.zoneLocationRepo.find({
        where: { zoneId },
        relations: ['location'],
      });
    return this.zoneLocationRepo.find({ relations: ['location'] });
  }

  async deleteZoneLocation(id: string) {
    const res = await this.zoneLocationRepo.delete(id);
    const deleted = (res.affected || 0) > 0;
    if (deleted) await this.invalidateShippingCaches();
    return deleted;
  }

  // Methods
  async createMethod(payload: CreateShippingMethodDto) {
    const method = this.methodRepo.create({
      code: payload.code,
      displayName: payload.displayName,
      provider: payload.provider,
      providerId: payload.providerId,
      isActive: payload.isActive ?? true,
      zoneId: null as any,
    } as any);
    const saved = await this.methodRepo.save(method);
    await this.invalidateShippingCaches();
    return saved;
  }

  async listMethods() {
    return this.methodRepo.find({
      relations: [
        'rates',
        'rates.currency',
        'rates.channels',
        'providerEntity',
      ] as any,
    });
  }

  async listMethodsForZone(zoneId: string) {
    const zone = await this.zoneRepo.findOne({ where: { id: zoneId } });
    if (!zone) throw new NotFoundException('Shipping zone not found');

    // Return attachments enriched with method + rates.
    return this.zoneMethodRepo.find({
      where: { zoneId },
      relations: [
        'method',
        'method.rates',
        'method.rates.currency',
        'method.rates.channels',
        'method.providerEntity',
      ] as any,
      order: { createdAt: 'DESC' as any },
    });
  }

  async attachMethodToZone(params: {
    zoneId: string;
    shippingMethodId: string;
    isActive?: boolean;
  }) {
    const zone = await this.zoneRepo.findOne({ where: { id: params.zoneId } });
    if (!zone) throw new NotFoundException('Shipping zone not found');

    const method = await this.methodRepo.findOne({
      where: { id: params.shippingMethodId },
    });
    if (!method) throw new NotFoundException('Shipping method not found');

    const existing = await this.zoneMethodRepo.findOne({
      where: { zoneId: params.zoneId, shippingMethodId: params.shippingMethodId },
      relations: [
        'method',
        'method.rates',
        'method.rates.currency',
        'method.rates.channels',
        'method.providerEntity',
      ] as any,
    });

    if (existing) {
      if (typeof params.isActive !== 'undefined') {
        existing.isActive = params.isActive;
        await this.zoneMethodRepo.save(existing);
        await this.invalidateShippingCaches();
      }
      return existing;
    }

    const row = this.zoneMethodRepo.create({
      zoneId: params.zoneId,
      shippingMethodId: params.shippingMethodId,
      isActive: params.isActive ?? true,
    });
    const saved = await this.zoneMethodRepo.save(row);
    const hydrated = await this.zoneMethodRepo.findOne({
      where: { id: saved.id },
      relations: [
        'method',
        'method.rates',
        'method.rates.currency',
        'method.rates.channels',
        'method.providerEntity',
      ] as any,
    });
    await this.invalidateShippingCaches();
    return hydrated ?? saved;
  }

  async getMethod(id: string) {
    const m = await this.methodRepo.findOne({
      where: { id },
      relations: [
        'rates',
        'rates.currency',
        'rates.channels',
        'providerEntity',
      ] as any,
    });
    if (!m) throw new NotFoundException('Shipping method not found');
    return m;
  }

  async updateMethod(id: string, payload: Partial<CreateShippingMethodDto>) {
    await this.methodRepo.update(id, {
      ...(typeof payload.code !== 'undefined' ? { code: payload.code } : {}),
      ...(typeof payload.displayName !== 'undefined'
        ? { displayName: payload.displayName }
        : {}),
      ...(typeof payload.provider !== 'undefined'
        ? { provider: payload.provider }
        : {}),
      ...(typeof payload.providerId !== 'undefined'
        ? { providerId: payload.providerId }
        : {}),
      ...(typeof payload.isActive !== 'undefined'
        ? { isActive: payload.isActive }
        : {}),
    } as any);
    await this.invalidateShippingCaches();
    return this.getMethod(id);
  }

  async deleteMethod(id: string) {
    const res = await this.methodRepo.delete(id);
    const deleted = (res.affected || 0) > 0;
    if (deleted) await this.invalidateShippingCaches();
    return deleted;
  }

  // Providers
  async createProvider(payload: {
    code: string;
    name: string;
    isActive?: boolean;
    metaJson?: Record<string, unknown>;
  }) {
    const row = this.providerRepo.create({
      code: String(payload.code).trim(),
      name: String(payload.name).trim(),
      isActive: payload.isActive ?? true,
      metaJson: payload.metaJson ?? {},
    });
    return this.providerRepo.save(row);
  }

  async listProviders() {
    return this.providerRepo.find({ order: { name: 'ASC' as any } });
  }

  async getProvider(id: string) {
    const row = await this.providerRepo.findOne({ where: { id } });
    if (!row) throw new NotFoundException('Shipping provider not found');
    return row;
  }

  async updateProvider(
    id: string,
    payload: Partial<{
      code: string;
      name: string;
      isActive: boolean;
      metaJson: Record<string, unknown>;
    }>,
  ) {
    await this.providerRepo.update(id, payload as any);
    return this.getProvider(id);
  }

  async deleteProvider(id: string) {
    const res = await this.providerRepo.delete(id);
    return (res.affected || 0) > 0;
  }

  // Rates
  async createRate(payload: CreateShippingRateDto) {
    // validate formula or table_rate metadata as needed
    if (payload.calculationType === 'formula') {
      const formula = (payload.metaJson as any)?.formula || payload.price;
      if (!formula)
        throw new BadRequestException(
          'Formula rate requires a formula expression in metaJson.formula or a formula in price',
        );
      try {
        validateFormula(String(formula));
      } catch (err: any) {
        throw new BadRequestException(
          `Invalid formula: ${err?.message || 'unknown error'}`,
        );
      }
    }

    if (payload.calculationType === 'table_rate') {
      const meta = payload.metaJson as any;
      if (!meta || !Array.isArray(meta.tiers) || meta.tiers.length === 0) {
        throw new BadRequestException(
          'table_rate requires metaJson.tiers array with at least one tier',
        );
      }
    }

    const { channelIds: _channelIds, ...rest } = payload as any;

    const normalizedCurrencyCode = rest.currencyCode
      ? await this.currencyService.assertExists(rest.currencyCode)
      : undefined;

    const channelIds: string[] | undefined = Array.isArray(_channelIds)
      ? (_channelIds as any[]).map(String)
      : undefined;

    let channels: Channel[] | undefined;
    if (channelIds && channelIds.length) {
      channels = await this.channelRepo.find({ where: { id: In(channelIds) } });
      if (channels.length !== channelIds.length) {
        throw new BadRequestException('One or more channels not found');
      }
    }

    const r = new ShippingRate();
    Object.assign(r, rest);
    r.currencyCode = normalizedCurrencyCode;
    r.channels = channels;

    const saved = await this.rateRepo.save(r);
    await this.invalidateShippingCaches();
    const hydrated = await this.rateRepo.findOne({
      where: { id: saved.id },
      relations: ['currency', 'channels'] as any,
    });
    return hydrated ?? saved;
  }

  async listRates(methodId?: string) {
    if (methodId)
      return this.rateRepo.find({
        where: { methodId },
        relations: ['currency', 'channels'] as any,
      });
    return this.rateRepo.find({ relations: ['currency', 'channels'] as any });
  }

  async getRate(id: string) {
    const r = await this.rateRepo.findOne({
      where: { id },
      relations: ['currency', 'channels'] as any,
    });
    if (!r) throw new NotFoundException('Shipping rate not found');
    return r;
  }

  async updateRate(id: string, payload: Partial<CreateShippingRateDto>) {
    // validate on update too if formula/table_rate provided
    if (
      payload.calculationType === 'formula' ||
      (payload.metaJson && (payload as any).metaJson?.formula)
    ) {
      const expr = (payload.metaJson as any)?.formula ?? payload.price;
      if (expr) {
        try {
          validateFormula(String(expr));
        } catch (err: any) {
          throw new BadRequestException(
            `Invalid formula: ${err?.message || 'unknown error'}`,
          );
        }
      }
    }
    if (
      payload.calculationType === 'table_rate' ||
      (payload.metaJson && (payload as any).metaJson?.tiers)
    ) {
      const meta = (payload as any).metaJson;
      if (!meta || !Array.isArray(meta.tiers) || meta.tiers.length === 0) {
        throw new BadRequestException(
          'table_rate requires metaJson.tiers array with at least one tier',
        );
      }
    }

    const { channelIds: _channelIds, ...rest } = payload as any;

    const normalizedCurrencyCode =
      typeof rest.currencyCode !== 'undefined'
        ? rest.currencyCode
          ? await this.currencyService.assertExists(rest.currencyCode)
          : null
        : undefined;

    const hasChannelIds = typeof _channelIds !== 'undefined';
    const channelIds: string[] | undefined = hasChannelIds
      ? (Array.isArray(_channelIds) ? (_channelIds as any[]).map(String) : [])
      : undefined;

    if (hasChannelIds) {
      const row = await this.rateRepo.findOne({
        where: { id },
        relations: ['channels'] as any,
      });
      if (!row) throw new NotFoundException('Shipping rate not found');

      const channels = channelIds?.length
        ? await this.channelRepo.find({ where: { id: In(channelIds) } })
        : [];

      if (channelIds && channels.length !== channelIds.length) {
        throw new BadRequestException('One or more channels not found');
      }

      row.channels = channels;
      await this.rateRepo.save(row);
    }

    await this.rateRepo.update(id, {
      ...(rest as any),
      ...(typeof normalizedCurrencyCode !== 'undefined'
        ? { currencyCode: normalizedCurrencyCode as any }
        : {}),
    } as any);
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
