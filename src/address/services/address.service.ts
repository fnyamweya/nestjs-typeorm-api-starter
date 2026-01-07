import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DeepPartial, ILike, Repository } from 'typeorm';
import { Address } from '../entities/address.entity';
import { UpsertAddressDto } from '../dto/upsert-address.dto';
import { GooglePlacesService } from 'src/common/google-places/google-places.service';
import { Location } from 'src/location/entities/location.entity';
import { CountryConfigService } from 'src/country/country-config.service';

@Injectable()
export class AddressService {
  constructor(
    @InjectRepository(Address)
    private readonly addressRepo: Repository<Address>,
    @InjectRepository(Location)
    private readonly locationRepo: Repository<Location>,
    private readonly googlePlaces: GooglePlacesService,
    private readonly countryConfig: CountryConfigService,
  ) {}

  private async enrichFromGoogle(payload: UpsertAddressDto): Promise<{
    countryCode?: string;
    fields: Record<string, unknown>;
    details: Parameters<GooglePlacesService['mapPlaceDetailsToAddress']>[0];
  } | null> {
    if (!payload.googlePlaceId) return null;

    const details = await this.googlePlaces.placeDetails({
      placeId: payload.googlePlaceId,
      sessionToken: payload.googleSessionToken,
    });

    const mapped = this.googlePlaces.mapPlaceDetailsToAddress(details);
    return {
      countryCode: mapped.countryCode,
      fields: mapped.fields,
      details,
    };
  }

  private async resolveBestEffortLocationId(params: {
    countryCode?: string;
    googleDetails: Parameters<
      GooglePlacesService['mapPlaceDetailsToAddress']
    >[0];
  }): Promise<{
    locationId: string;
    matchedType: string;
    matchedName: string;
  } | null> {
    const countryCode = params.countryCode?.toUpperCase();
    if (!countryCode) return null;

    const candidates =
      await this.countryConfig.extractLocationCandidatesFromGoogle(
        params.googleDetails,
        countryCode,
      );

    for (const c of candidates) {
      // Strict match: name ILIKE 'Exact Name' (case-insensitive equals)
      const found = await this.locationRepo.findOne({
        where: {
          countryCode,
          type: c.type,
          name: ILike(c.name),
        } as any,
      });
      if (found) {
        return {
          locationId: found.id,
          matchedType: String(c.type),
          matchedName: c.name,
        };
      }
    }

    return null;
  }

  async create(payload: UpsertAddressDto): Promise<Address> {
    const google = await this.enrichFromGoogle(payload);
    const normalizedCountry = payload.countryCode?.toUpperCase();
    if (
      google?.countryCode &&
      normalizedCountry &&
      google.countryCode.toUpperCase() !== normalizedCountry
    ) {
      throw new BadRequestException(
        'countryCode does not match Google Place country',
      );
    }

    const bestCountryCode = (
      normalizedCountry || google?.countryCode
    )?.toUpperCase();
    const bestEffortLocation =
      !payload.locationId && google?.details
        ? await this.resolveBestEffortLocationId({
            countryCode: bestCountryCode,
            googleDetails: google.details,
          })
        : null;

    const entity = this.addressRepo.create({
      ...(payload as DeepPartial<Address>),
      countryCode: bestCountryCode,
      locationId: payload.locationId ?? bestEffortLocation?.locationId,
      fieldsJson: {
        ...(google?.fields ?? {}),
        ...(payload.fields ?? {}),
        ...(bestEffortLocation
          ? {
              locationMatch: {
                source: 'google',
                matchedType: bestEffortLocation.matchedType,
                matchedName: bestEffortLocation.matchedName,
                locationId: bestEffortLocation.locationId,
              },
            }
          : {}),
      } as any,
    } as DeepPartial<Address>);
    return this.addressRepo.save(entity);
  }

  async update(id: string, payload: UpsertAddressDto): Promise<Address> {
    const existing = await this.addressRepo.findOne({ where: { id } });
    if (!existing) throw new NotFoundException('Address not found');

    const google = await this.enrichFromGoogle(payload);
    const normalizedCountry = (
      payload.countryCode || existing.countryCode
    )?.toUpperCase();
    if (
      google?.countryCode &&
      normalizedCountry &&
      google.countryCode.toUpperCase() !== normalizedCountry
    ) {
      throw new BadRequestException(
        'countryCode does not match Google Place country',
      );
    }

    const bestCountryCode = (
      normalizedCountry || google?.countryCode
    )?.toUpperCase();
    const bestEffortLocation =
      !payload.locationId && !existing.locationId && google?.details
        ? await this.resolveBestEffortLocationId({
            countryCode: bestCountryCode,
            googleDetails: google.details,
          })
        : null;

    const { fields, ...rest } = payload as any;
    Object.assign(existing, rest);
    if (bestCountryCode) existing.countryCode = bestCountryCode;

    if (payload.locationId) {
      existing.locationId = payload.locationId;
    } else if (!existing.locationId && bestEffortLocation?.locationId) {
      existing.locationId = bestEffortLocation.locationId;
    }

    if (google?.fields) {
      existing.fieldsJson = {
        ...(existing.fieldsJson ?? {}),
        ...(google.fields ?? {}),
      };
    }

    if (bestEffortLocation) {
      existing.fieldsJson = {
        ...(existing.fieldsJson ?? {}),
        locationMatch: {
          source: 'google',
          matchedType: bestEffortLocation.matchedType,
          matchedName: bestEffortLocation.matchedName,
          locationId: bestEffortLocation.locationId,
        },
      };
    }

    if (fields) {
      existing.fieldsJson = {
        ...(existing.fieldsJson ?? {}),
        ...(fields ?? {}),
      };
    }
    return this.addressRepo.save(existing);
  }

  async get(id: string): Promise<Address> {
    const existing = await this.addressRepo.findOne({ where: { id } });
    if (!existing) throw new NotFoundException('Address not found');
    return existing;
  }

  async delete(id: string): Promise<boolean> {
    const res = await this.addressRepo.delete(id);
    return (res.affected || 0) > 0;
  }
}
