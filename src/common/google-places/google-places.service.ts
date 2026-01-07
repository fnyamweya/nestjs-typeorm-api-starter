import { HttpService } from '@nestjs/axios';
import {
  BadRequestException,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export type GooglePlacesAutocompletePrediction = {
  placeId: string;
  description: string;
  mainText?: string;
  secondaryText?: string;
  types?: string[];
};

export type GooglePlaceDetails = {
  placeId: string;
  name?: string;
  formattedAddress?: string;
  lat?: number;
  lng?: number;
  addressComponents?: Array<{
    longName: string;
    shortName: string;
    types: string[];
  }>;
  types?: string[];
  raw: unknown;
};

export type GoogleMappedAddress = {
  countryCode?: string;
  fields: Record<string, unknown>;
  raw: unknown;
};

@Injectable()
export class GooglePlacesService {
  private readonly logger = new Logger(GooglePlacesService.name);

  constructor(
    private readonly http: HttpService,
    private readonly config: ConfigService,
  ) {}

  private getApiKey(): string {
    const key =
      this.config.get<string>('GOOGLE_MAPS_API_KEY') ||
      this.config.get<string>('GOOGLE_PLACES_API_KEY');

    if (!key) {
      throw new ServiceUnavailableException(
        'Google Places is not configured (set GOOGLE_MAPS_API_KEY)',
      );
    }

    return key;
  }

  async autocomplete(params: {
    input: string;
    countryCode?: string;
    language?: string;
    sessionToken?: string;
  }): Promise<GooglePlacesAutocompletePrediction[]> {
    if (!params.input?.trim()) {
      throw new BadRequestException('input is required');
    }

    const key = this.getApiKey();
    const url = 'https://maps.googleapis.com/maps/api/place/autocomplete/json';

    try {
      const res = await firstValueFrom(
        this.http.get(url, {
          params: {
            key,
            input: params.input,
            language: params.language,
            sessiontoken: params.sessionToken,
            components: params.countryCode
              ? `country:${String(params.countryCode).toLowerCase()}`
              : undefined,
          },
          timeout: 7000,
        }),
      );

      const data: any = res.data;
      if (!data)
        throw new ServiceUnavailableException('Google Places returned no data');

      if (data.status !== 'OK' && data.status !== 'ZERO_RESULTS') {
        throw new BadRequestException(
          data.error_message ||
            `Google Places autocomplete failed (${data.status})`,
        );
      }

      const predictions: any[] = data.predictions ?? [];
      return predictions.map((p) => ({
        placeId: p.place_id,
        description: p.description,
        mainText: p.structured_formatting?.main_text,
        secondaryText: p.structured_formatting?.secondary_text,
        types: p.types,
      }));
    } catch (err: any) {
      this.logger.warn(
        `autocomplete failed: ${err?.message ?? 'unknown error'}`,
      );
      if (err instanceof BadRequestException) throw err;
      throw new ServiceUnavailableException(
        'Google Places autocomplete unavailable',
      );
    }
  }

  async placeDetails(params: {
    placeId: string;
    language?: string;
    sessionToken?: string;
  }): Promise<GooglePlaceDetails> {
    if (!params.placeId?.trim()) {
      throw new BadRequestException('placeId is required');
    }

    const key = this.getApiKey();
    const url = 'https://maps.googleapis.com/maps/api/place/details/json';

    try {
      const res = await firstValueFrom(
        this.http.get(url, {
          params: {
            key,
            place_id: params.placeId,
            language: params.language,
            sessiontoken: params.sessionToken,
            fields: [
              'place_id',
              'name',
              'formatted_address',
              'geometry/location',
              'address_component',
              'types',
            ].join(','),
          },
          timeout: 7000,
        }),
      );

      const data: any = res.data;
      if (!data)
        throw new ServiceUnavailableException('Google Places returned no data');

      if (data.status !== 'OK') {
        throw new BadRequestException(
          data.error_message || `Google Places details failed (${data.status})`,
        );
      }

      const r: any = data.result;
      const comps: any[] = r.address_components ?? [];
      const lat = r.geometry?.location?.lat;
      const lng = r.geometry?.location?.lng;

      return {
        placeId: r.place_id,
        name: r.name,
        formattedAddress: r.formatted_address,
        lat: typeof lat === 'number' ? lat : undefined,
        lng: typeof lng === 'number' ? lng : undefined,
        addressComponents: comps.map((c) => ({
          longName: c.long_name,
          shortName: c.short_name,
          types: c.types ?? [],
        })),
        types: r.types ?? [],
        raw: r,
      };
    } catch (err: any) {
      this.logger.warn(
        `placeDetails failed: ${err?.message ?? 'unknown error'}`,
      );
      if (err instanceof BadRequestException) throw err;
      throw new ServiceUnavailableException(
        'Google Places details unavailable',
      );
    }
  }

  mapPlaceDetailsToAddress(details: GooglePlaceDetails): GoogleMappedAddress {
    const compByType = new Map<
      string,
      { longName: string; shortName: string }
    >();
    for (const c of details.addressComponents ?? []) {
      for (const t of c.types ?? []) {
        if (!compByType.has(t))
          compByType.set(t, { longName: c.longName, shortName: c.shortName });
      }
    }

    const country = compByType.get('country');

    const streetNumber = compByType.get('street_number')?.longName;
    const route = compByType.get('route')?.longName;
    const premise = compByType.get('premise')?.longName;
    const subpremise = compByType.get('subpremise')?.longName;

    const locality = compByType.get('locality')?.longName;
    const sublocality = compByType.get('sublocality')?.longName;
    const neighborhood = compByType.get('neighborhood')?.longName;

    const admin1 = compByType.get('administrative_area_level_1');
    const admin2 = compByType.get('administrative_area_level_2');

    const postalCode = compByType.get('postal_code')?.longName;

    const line1Parts = [streetNumber, route].filter(Boolean);
    const line1 = line1Parts.length ? line1Parts.join(' ') : undefined;

    const city = locality || sublocality || neighborhood;

    const fields: Record<string, unknown> = {
      line1,
      premise,
      unit: subpremise,
      city,
      region: admin1?.longName,
      regionCode: admin1?.shortName,
      district: admin2?.longName,
      postalCode,
      formattedAddress: details.formattedAddress,
      geo:
        details.lat !== undefined && details.lng !== undefined
          ? { lat: details.lat, lng: details.lng }
          : undefined,
      google: {
        placeId: details.placeId,
        name: details.name,
        types: details.types,
        addressComponents: details.addressComponents,
        formattedAddress: details.formattedAddress,
      },
    };

    // remove undefined keys for cleanliness
    for (const k of Object.keys(fields)) {
      if (fields[k] === undefined) delete fields[k];
    }

    return {
      countryCode: country?.shortName,
      fields,
      raw: details.raw,
    };
  }
}
