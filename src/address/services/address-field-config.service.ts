import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AddressFieldConfig } from '../entities/address-field-config.entity';
import { LocationType } from '../../location/entities/location.entity';

const DEFAULT_KE_SCHEMA: Record<string, unknown> = {
  version: 1,
  // Frontend can use this to drive parent->child selection via /api/v1/locations
  locationChain: ['country', 'county', 'sub_county', 'ward', 'town'],
  fields: [
    { key: 'firstName', type: 'text', required: true },
    { key: 'lastName', type: 'text', required: true },
    { key: 'phone', type: 'text', required: true },
    // The following live in Address.fieldsJson
    { key: 'addressLine1', type: 'text', required: true },
    { key: 'addressLine2', type: 'text', required: false },
    { key: 'notes', type: 'text', required: false },
  ],
};

@Injectable()
export class AddressFieldConfigService {
  constructor(
    @InjectRepository(AddressFieldConfig)
    private readonly repo: Repository<AddressFieldConfig>,
  ) {}

  async getActive(countryCode: string) {
    const code = (countryCode || 'KE').toUpperCase();

    const row = await this.repo.findOne({
      where: { countryCode: code, isActive: true },
      order: { updatedAt: 'DESC' },
    });

    if (row) return row;

    // fallback to default schema if not configured
    return {
      id: null,
      countryCode: code,
      isActive: true,
      schemaJson:
        code === 'KE' ? DEFAULT_KE_SCHEMA : { version: 1, fields: [] },
    };
  }

  async upsertActive(countryCode: string, schemaJson: Record<string, unknown>) {
    const code = (countryCode || 'KE').toUpperCase();

    let row = await this.repo.findOne({
      where: { countryCode: code, isActive: true },
    });

    if (!row) {
      row = this.repo.create({ countryCode: code, isActive: true, schemaJson });
    } else {
      row.schemaJson = schemaJson;
    }

    return this.repo.save(row);
  }

  async getLocationChain(countryCode: string): Promise<string[]> {
    const active = await this.getActive(countryCode);
    const schemaJson = (active as any)?.schemaJson as
      | Record<string, unknown>
      | undefined;
    const raw = schemaJson?.locationChain ?? [];

    // If not configured, fall back to a sensible default for KE (and generic otherwise)
    const fallback: string[] =
      (countryCode || 'KE').toUpperCase() === 'KE'
        ? [
            LocationType.COUNTRY,
            LocationType.COUNTY,
            LocationType.SUB_COUNTY,
            LocationType.WARD,
            LocationType.TOWN,
          ]
        : [LocationType.COUNTRY];

    const chain = Array.isArray(raw) ? raw : [];
    const normalized = chain
      .map((t) => String(t))
      .map((t) => t.trim().toLowerCase())
      .filter((t) => !!t);

    return normalized.length ? normalized : fallback;
  }
}
