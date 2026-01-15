import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, ILike, IsNull, Repository } from 'typeorm';
import { Location, LocationType } from '../entities/location.entity';
import { CountryConfig } from 'src/country/entities/country-config.entity';
import { CreateLocationDto } from '../dto/create-location.dto';
import { ListLocationsDto } from '../dto/list-locations.dto';
import { UpdateLocationDto } from '../dto/update-location.dto';
import { AddressFieldConfigService } from '../../address/services/address-field-config.service';

@Injectable()
export class LocationService {
  constructor(
    @InjectRepository(Location)
    private readonly locationRepo: Repository<Location>,
    @InjectRepository(CountryConfig)
    private readonly countryConfigRepo: Repository<CountryConfig>,
    private readonly dataSource: DataSource,
    private readonly addressFieldConfigService: AddressFieldConfigService,
  ) {}

  private async getCountryConfig(countryId: string): Promise<CountryConfig> {
    const row = await this.countryConfigRepo.findOne({ where: { id: countryId } });
    if (!row) throw new NotFoundException('Country not found');
    return row;
  }

  private async getChain(countryCode: string): Promise<string[]> {
    return this.addressFieldConfigService.getLocationChain(countryCode);
  }

  private allowedChildTypesFromChain(
    chain: string[],
    parentType: string,
  ): string[] {
    const idx = chain.indexOf(parentType);
    if (idx < 0) return [];
    const next = chain[idx + 1];
    return next ? [next] : [];
  }

  async getAllowedChildTypes(params: {
    countryId: string;
    parentType?: string;
    parentId?: string;
  }) {
    const country = await this.getCountryConfig(params.countryId);
    const countryCode = country.countryCode?.toUpperCase();
    if (!countryCode) throw new BadRequestException('countryCode is missing');
    const chain = await this.getChain(countryCode);

    if (params.parentId) {
      const parent = await this.locationRepo.findOne({
        where: { id: params.parentId },
      });
      if (!parent) throw new NotFoundException('Parent location not found');
      if (parent.countryId && parent.countryId !== country.id) {
        throw new BadRequestException('countryId must match parent countryId');
      }
      return {
        countryId: country.id,
        countryCode,
        parentType: parent.type,
        allowedChildTypes: this.allowedChildTypesFromChain(chain, parent.type),
        chain,
      };
    }

    if (!params.parentType) {
      // root creation: first item in chain
      return {
        countryId: country.id,
        countryCode,
        parentType: null,
        allowedChildTypes: chain.length ? [chain[0]] : [LocationType.COUNTRY],
        chain,
      };
    }

    return {
      countryId: country.id,
      countryCode,
      parentType: params.parentType,
      allowedChildTypes: this.allowedChildTypesFromChain(
        chain,
        params.parentType,
      ),
      chain,
    };
  }

  async getById(id: string): Promise<Location> {
    const row = await this.locationRepo.findOne({ where: { id } });
    if (!row) throw new NotFoundException('Location not found');
    return row;
  }

  async list(params: ListLocationsDto): Promise<Location[]> {
    // Optional guardrails: if caller provides countryId + type, ensure the type is in that country's chain.
    if (params.countryId && params.type) {
      const country = await this.getCountryConfig(params.countryId);
      const chain = await this.getChain(country.countryCode);
      if (chain.length && !chain.includes(params.type)) {
        throw new BadRequestException(
          `Invalid type '${params.type}' for country '${country.countryCode}'. Allowed: ${chain.join(', ')}`,
        );
      }
    }

    // Backward-compatible listing behavior:
    // - When no parentId is provided, default to roots (parent IS NULL)
    // - When searching with q, search across the whole tree unless parentId is explicitly provided
    const where: any = {
      ...(params.countryId ? { countryId: params.countryId } : {}),
      ...(params.type ? { type: params.type } : {}),
      ...(params.q ? { name: ILike(`%${params.q}%`) } : {}),
      ...(params.parentId
        ? { parent: { id: params.parentId } }
        : params.q
          ? {}
          : { parent: IsNull() }),
    };

    return this.locationRepo.find({ where, order: { name: 'ASC' } });
  }

  async getTreeByCountryId(countryId: string): Promise<Location[]> {
    const treeRepo = this.dataSource.getTreeRepository(Location);
    // Return root trees for a given countryCode
    const roots = await this.locationRepo.find({
      where: { countryId, parent: IsNull() },
      order: { name: 'ASC' },
    });

    const trees: Location[] = [];
    for (const root of roots) {
      trees.push(await treeRepo.findDescendantsTree(root));
    }
    return trees;
  }

  async create(payload: CreateLocationDto): Promise<Location> {
    const country = await this.getCountryConfig(payload.countryId);
    const countryCode = country.countryCode?.toUpperCase();
    if (!countryCode) throw new BadRequestException('countryCode is required');

    const chain = await this.getChain(countryCode);

    let parent: Location | undefined;
    if (payload.parentId) {
      const foundParent = await this.locationRepo.findOne({
        where: { id: payload.parentId },
      });
      if (!foundParent)
        throw new NotFoundException('Parent location not found');
      parent = foundParent;

      if (parent.countryId && parent.countryId !== country.id) {
        throw new BadRequestException(
          'countryId must match parent countryId',
        );
      }

      const allowed = this.allowedChildTypesFromChain(chain, parent.type);
      if (!allowed.includes(payload.type)) {
        throw new BadRequestException(
          `Invalid child type '${payload.type}' under parent type '${parent.type}'`,
        );
      }
    } else {
      // Root nodes should be countries
      const allowedRoot = chain.length ? chain[0] : LocationType.COUNTRY;
      if (payload.type !== allowedRoot) {
        throw new BadRequestException(
          `Root locations must have type='${allowedRoot}'`,
        );
      }
    }

    const entity = this.locationRepo.create({
      name: payload.name,
      type: payload.type,
      countryId: country.id,
      countryCode,
      code: payload.code,
      parent,
      metaJson: payload.metaJson ?? {},
    });

    return this.locationRepo.save(entity);
  }

  async update(id: string, payload: UpdateLocationDto): Promise<Location> {
    const existing = await this.locationRepo.findOne({
      where: { id },
      relations: ['parent'],
    });
    if (!existing) throw new NotFoundException('Location not found');

    const countryId = payload.countryId ?? existing.countryId;
    if (!countryId) throw new BadRequestException('countryId is required');
    const country = await this.getCountryConfig(countryId);
    const countryCode = country.countryCode?.toUpperCase();
    if (!countryCode) throw new BadRequestException('countryCode is required');
    const chain = await this.getChain(countryCode);

    // parent move (optional)
    let parent: Location | undefined = existing.parent;
    if (typeof payload.parentId !== 'undefined') {
      if (!payload.parentId) {
        parent = undefined;
      } else {
        if (payload.parentId === existing.id) {
          throw new BadRequestException('parentId cannot equal id');
        }

        const foundParent = await this.locationRepo.findOne({
          where: { id: payload.parentId },
        });
        if (!foundParent)
          throw new NotFoundException('Parent location not found');

        // prevent cycles
        const treeRepo = this.dataSource.getTreeRepository(Location);
        const descendants = await treeRepo.findDescendants(existing);
        const descendantIds = new Set(descendants.map((d) => d.id));
        if (descendantIds.has(foundParent.id)) {
          throw new BadRequestException(
            'Cannot move a location under its descendant',
          );
        }

        if (foundParent.countryId && foundParent.countryId !== countryId) {
          throw new BadRequestException(
            'countryId must match parent countryId',
          );
        }

        const targetType = payload.type ?? existing.type;
        const allowed = this.allowedChildTypesFromChain(
          chain,
          foundParent.type,
        );
        if (!allowed.includes(targetType)) {
          throw new BadRequestException(
            `Invalid child type '${targetType}' under parent type '${foundParent.type}'`,
          );
        }

        parent = foundParent;
      }
    }

    // root rules
    if (!parent) {
      const allowedRoot = chain.length ? chain[0] : LocationType.COUNTRY;
      const targetType = payload.type ?? existing.type;
      if (targetType !== allowedRoot) {
        throw new BadRequestException(
          `Root locations must have type='${allowedRoot}'`,
        );
      }
    }

    if (payload.type && parent) {
      const allowed = this.allowedChildTypesFromChain(chain, parent.type);
      if (!allowed.includes(payload.type)) {
        throw new BadRequestException(
          `Invalid child type '${payload.type}' under parent type '${parent.type}'`,
        );
      }
    }

    existing.countryId = countryId;
    existing.countryCode = countryCode;
    if (typeof payload.name !== 'undefined') existing.name = payload.name;
    if (typeof payload.code !== 'undefined') existing.code = payload.code;
    if (typeof payload.type !== 'undefined') existing.type = payload.type;
    if (typeof payload.metaJson !== 'undefined')
      existing.metaJson = payload.metaJson ?? {};
    existing.parent = parent;

    return this.locationRepo.save(existing);
  }

  async delete(
    id: string,
    opts?: { force?: boolean },
  ): Promise<{ deleted: boolean }> {
    const existing = await this.locationRepo.findOne({ where: { id } });
    if (!existing) throw new NotFoundException('Location not found');

    if (!opts?.force) {
      const children = await this.locationRepo.count({
        where: { parent: { id } as any },
      });
      if (children > 0) {
        throw new BadRequestException(
          'Location has children. Use force=true to delete recursively.',
        );
      }
    }

    const res = await this.locationRepo.delete(id);
    return { deleted: (res.affected || 0) > 0 };
  }
}
