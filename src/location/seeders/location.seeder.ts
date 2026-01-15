import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DeepPartial, Repository } from 'typeorm';
import { Location, LocationType } from '../entities/location.entity';
import { KENYA_LOCATION_TREE, SeedLocationNode } from './ke-locations.seed';
import { CountryConfig } from 'src/country/entities/country-config.entity';

@Injectable()
export class LocationSeeder {
  constructor(
    @InjectRepository(Location)
    private readonly locationRepo: Repository<Location>,
    @InjectRepository(CountryConfig)
    private readonly countryConfigRepo: Repository<CountryConfig>,
  ) {}

  private async upsertNode(
    node: SeedLocationNode,
    country: CountryConfig,
    parent?: Location,
  ): Promise<Location> {
    // Ensure idempotency by matching on (name,type,parent)
    const existing = await this.locationRepo.findOne({
      where: {
        name: node.name,
        type: node.type,
        countryId: country.id,
        ...(parent ? { parent: { id: parent.id } } : { parent: null }),
      } as any,
    });

    let entity: Location;
    if (existing) {
      entity = existing;
    } else {
      entity = this.locationRepo.create({
        name: node.name,
        type: node.type,
        code: node.code,
        countryId: country.id,
        countryCode: country.countryCode,
        parent: parent ?? null,
      } as DeepPartial<Location>);
      entity = await this.locationRepo.save(entity);
    }

    if (node.children?.length) {
      for (const child of node.children) {
        await this.upsertNode(child, country, entity);
      }
    }

    return entity;
  }

  async seedKenya(): Promise<void> {
    const countryCode = 'KE';
    let country = await this.countryConfigRepo.findOne({
      where: { countryCode, isActive: true },
    });
    if (!country) {
      country = await this.countryConfigRepo.save(
        this.countryConfigRepo.create({
          countryCode,
          isActive: true,
          configJson: { version: 1 },
        }),
      );
    }

    // root must be a COUNTRY node
    const root: SeedLocationNode = {
      ...KENYA_LOCATION_TREE,
      type: LocationType.COUNTRY,
      code: 'KE',
    };

    await this.upsertNode(root, country);
  }

  async seed(): Promise<void> {
    await this.seedKenya();
  }
}
