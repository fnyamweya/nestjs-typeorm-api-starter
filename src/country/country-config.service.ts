import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { LocationType } from 'src/location/entities/location.entity';
import { GooglePlaceDetails } from 'src/common/google-places/google-places.service';
import { CountryConfig } from './entities/country-config.entity';
import { CurrencyService } from 'src/currency/currency.service';

export type GoogleAdminComponentType =
  | 'country'
  | 'administrative_area_level_1'
  | 'administrative_area_level_2'
  | 'administrative_area_level_3'
  | 'administrative_area_level_4'
  | 'locality'
  | 'postal_town'
  | 'sublocality'
  | 'sublocality_level_1'
  | 'neighborhood'
  | 'postal_code'
  | string;

export type CountryGoogleLocationMapping = {
  /** ISO2 country code, upper-case (e.g. KE) */
  countryCode: string;

  /**
   * Ordered mapping rules from Google address components to our internal LocationType.
   * We try candidates in this order (more specific first) and pick the first strict match.
   */
  candidates: Array<{
    locationType: LocationType;
    googleComponentTypes: GoogleAdminComponentType[];
  }>;
};

@Injectable()
export class CountryConfigService {
  constructor(
    @InjectRepository(CountryConfig)
    private readonly repo: Repository<CountryConfig>,
    private readonly currencyService: CurrencyService,
  ) {}

  /**
   * Default rules (used as fallback when DB config is missing).
   * Kenya rules:
   * - Location chain (typical): county -> sub_county -> ward -> town
   * - Google components used:
   *   - county: administrative_area_level_1
   *   - sub_county: administrative_area_level_2
   *   - ward: administrative_area_level_3 OR sublocality_level_1
   *   - town: locality OR postal_town OR neighborhood
   */
  private readonly defaultConfigs: Record<string, Record<string, unknown>> = {
    KE: {
      version: 1,
      googleLocationMapping: {
        candidates: [
          {
            locationType: LocationType.TOWN,
            googleComponentTypes: ['locality', 'postal_town', 'neighborhood'],
          },
          {
            locationType: LocationType.WARD,
            googleComponentTypes: [
              'administrative_area_level_3',
              'sublocality_level_1',
              'sublocality',
            ],
          },
          {
            locationType: LocationType.SUB_COUNTY,
            googleComponentTypes: ['administrative_area_level_2'],
          },
          {
            locationType: LocationType.COUNTY,
            googleComponentTypes: ['administrative_area_level_1'],
          },
        ],
      },
    },
  };

  private isRecord(value: unknown): value is Record<string, unknown> {
    return !!value && typeof value === 'object' && !Array.isArray(value);
  }

  /**
   * Validates a known subset of keys but allows extra parameters.
   * This keeps config extensible (currencies, future country rules) while preventing obvious shape errors.
   */
  private validateConfigJson(configJson: Record<string, unknown>) {
    if (!this.isRecord(configJson)) {
      throw new BadRequestException('config must be an object');
    }

    const version = configJson.version;
    if (version !== undefined) {
      if (
        typeof version !== 'number' ||
        !Number.isFinite(version) ||
        version < 1
      ) {
        throw new BadRequestException('config.version must be a number >= 1');
      }
    }

    const currencies = configJson.currencies;
    if (currencies !== undefined) {
      if (
        !Array.isArray(currencies) ||
        currencies.some((c) => typeof c !== 'string' || c.trim().length !== 3)
      ) {
        throw new BadRequestException(
          'config.currencies must be an array of 3-letter currency codes',
        );
      }
    }

    const glm = configJson.googleLocationMapping;
    if (glm !== undefined) {
      if (!this.isRecord(glm)) {
        throw new BadRequestException(
          'config.googleLocationMapping must be an object',
        );
      }

      const candidates = (glm as any).candidates;
      if (candidates !== undefined) {
        if (!Array.isArray(candidates)) {
          throw new BadRequestException(
            'config.googleLocationMapping.candidates must be an array',
          );
        }

        const allowed = new Set(Object.values(LocationType));

        for (const [i, item] of candidates.entries()) {
          if (!this.isRecord(item)) {
            throw new BadRequestException(
              `config.googleLocationMapping.candidates[${i}] must be an object`,
            );
          }

          const locationType = (item as any).locationType;
          const googleComponentTypes = (item as any).googleComponentTypes;

          if (!allowed.has(locationType)) {
            throw new BadRequestException(
              `config.googleLocationMapping.candidates[${i}].locationType must be a valid LocationType`,
            );
          }

          if (
            !Array.isArray(googleComponentTypes) ||
            !googleComponentTypes.length ||
            googleComponentTypes.some(
              (t: any) => typeof t !== 'string' || !t.trim(),
            )
          ) {
            throw new BadRequestException(
              `config.googleLocationMapping.candidates[${i}].googleComponentTypes must be a non-empty string array`,
            );
          }
        }
      }
    }
  }

  private async normalizeAndValidateCurrencies(
    configJson: Record<string, unknown>,
  ) {
    const currencies = (configJson as any).currencies;
    if (!Array.isArray(currencies)) return configJson;

    const normalized: string[] = [];
    for (const c of currencies) {
      const code = await this.currencyService.assertExists(c);
      normalized.push(code);
    }

    return { ...configJson, currencies: Array.from(new Set(normalized)) };
  }

  async getActive(countryCode: string) {
    const code = (countryCode || 'KE').toUpperCase();

    const row = await this.repo.findOne({
      where: { countryCode: code, isActive: true },
      order: { updatedAt: 'DESC' },
    });

    if (row) return row;

    return {
      id: null,
      countryCode: code,
      isActive: true,
      configJson: this.defaultConfigs[code] ?? { version: 1 },
    };
  }

  async upsertActive(countryCode: string, configJson: Record<string, unknown>) {
    const code = (countryCode || 'KE').toUpperCase();

    this.validateConfigJson(configJson);

    const normalizedConfig =
      await this.normalizeAndValidateCurrencies(configJson);

    let row = await this.repo.findOne({
      where: { countryCode: code, isActive: true },
    });

    if (!row) {
      row = this.repo.create({
        countryCode: code,
        isActive: true,
        configJson: normalizedConfig,
      });
    } else {
      row.configJson = normalizedConfig;
    }

    return this.repo.save(row);
  }

  private normalizeMappingFromConfig(
    countryCode: string,
    configJson: Record<string, unknown>,
  ): CountryGoogleLocationMapping | null {
    const raw = (configJson?.googleLocationMapping as any)?.candidates;
    if (!Array.isArray(raw)) return null;

    const allowed = new Set(Object.values(LocationType));
    const candidates: CountryGoogleLocationMapping['candidates'] = [];

    for (const item of raw) {
      const locationType = item?.locationType;
      const googleComponentTypes = item?.googleComponentTypes;

      if (!allowed.has(locationType)) continue;
      if (!Array.isArray(googleComponentTypes) || !googleComponentTypes.length)
        continue;

      candidates.push({
        locationType,
        googleComponentTypes: googleComponentTypes.map((t: any) => String(t)),
      });
    }

    if (!candidates.length) return null;

    return { countryCode: countryCode.toUpperCase(), candidates };
  }

  async getCountryGoogleLocationMapping(
    countryCode?: string,
  ): Promise<CountryGoogleLocationMapping | null> {
    if (!countryCode) return null;
    const code = String(countryCode).toUpperCase();

    const active = await this.getActive(code);
    const cfg = this.normalizeMappingFromConfig(
      code,
      (active as any)?.configJson ?? {},
    );
    if (cfg) return cfg;

    // Fallback to defaults if config exists but doesn't define a valid mapping.
    const fallback = this.defaultConfigs[code] ?? {};
    return this.normalizeMappingFromConfig(code, fallback) ?? null;
  }

  /** Extract candidate names for internal Location matching (strict case-insensitive equals). */
  async extractLocationCandidatesFromGoogle(
    details: GooglePlaceDetails,
    countryCode?: string,
  ): Promise<Array<{ type: LocationType; name: string }>> {
    const cfg = await this.getCountryGoogleLocationMapping(countryCode);
    if (!cfg) return [];

    const byType = new Map<string, string>();
    for (const c of details.addressComponents ?? []) {
      for (const t of c.types ?? []) {
        if (!byType.has(t)) byType.set(t, c.longName);
      }
    }

    const out: Array<{ type: LocationType; name: string }> = [];

    for (const rule of cfg.candidates) {
      for (const googleType of rule.googleComponentTypes) {
        const name = byType.get(googleType);
        if (name && name.trim()) {
          out.push({ type: rule.locationType, name: name.trim() });
          break;
        }
      }
    }

    // De-dupe by type+name preserving order.
    const seen = new Set<string>();
    return out.filter((c) => {
      const k = `${c.type}:${c.name.toLowerCase()}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }
}
