import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, ILike, IsNull, Repository } from 'typeorm';
import { Location, LocationType } from '../entities/location.entity';
import { CreateLocationDto } from '../dto/create-location.dto';
import { ListLocationsDto } from '../dto/list-locations.dto';
import { UpdateLocationDto } from '../dto/update-location.dto';
import { AddressFieldConfigService } from '../../address/services/address-field-config.service';

@Injectable()
export class LocationService {
  constructor(
    @InjectRepository(Location)
    private readonly locationRepo: Repository<Location>,
    private readonly dataSource: DataSource,
    private readonly addressFieldConfigService: AddressFieldConfigService,
  ) {}

  private normalizeCountryCode(countryCode?: string) {
    return (countryCode || '').toUpperCase();
  }

  private async getChain(countryCode: string): Promise<string[]> {
    return this.addressFieldConfigService.getLocationChain(countryCode);
  }

  private allowedChildTypesFromChain(chain: string[], parentType: string): string[] {
    const idx = chain.indexOf(parentType);
    if (idx < 0) return [];
    const next = chain[idx + 1];
    return next ? [next] : [];
  }

  async getAllowedChildTypes(params: { countryCode: string; parentType?: string; parentId?: string }) {
    const countryCode = this.normalizeCountryCode(params.countryCode);
    const chain = await this.getChain(countryCode);

    if (params.parentId) {
      const parent = await this.locationRepo.findOne({ where: { id: params.parentId } });
      if (!parent) throw new NotFoundException('Parent location not found');
      return {
        countryCode,
        parentType: parent.type,
        allowedChildTypes: this.allowedChildTypesFromChain(chain, parent.type),
        chain,
      };
    }

    if (!params.parentType) {
      // root creation: first item in chain
      return {
        countryCode,
        parentType: null,
        allowedChildTypes: chain.length ? [chain[0]] : [LocationType.COUNTRY],
        chain,
      };
    }

    return {
      countryCode,
      parentType: params.parentType,
      allowedChildTypes: this.allowedChildTypesFromChain(chain, params.parentType),
      chain,
    };
  }

  async getById(id: string): Promise<Location> {
    const row = await this.locationRepo.findOne({ where: { id } });
    if (!row) throw new NotFoundException('Location not found');
    return row;
  }

  async list(params: ListLocationsDto): Promise<Location[]> {
    // Optional guardrails: if caller provides countryCode + type, ensure the type is in that country's chain.
    if (params.countryCode && params.type) {
      const chain = await this.getChain(this.normalizeCountryCode(params.countryCode));
      if (chain.length && !chain.includes(params.type)) {
        throw new BadRequestException(
          `Invalid type '${params.type}' for country '${params.countryCode}'. Allowed: ${chain.join(', ')}`,
        );
      }
    }

    const where: any = {
      ...(params.countryCode ? { countryCode: params.countryCode } : {}),
      ...(params.type ? { type: params.type } : {}),
      ...(params.q ? { name: ILike(`%${params.q}%`) } : {}),
      ...(params.parentId
        ? { parent: { id: params.parentId } }
        : { parent: IsNull() }),
    };

    return this.locationRepo.find({ where, order: { name: 'ASC' } });
  }

  async getTreeByCountryCode(countryCode: string): Promise<Location[]> {
    const treeRepo = this.dataSource.getTreeRepository(Location);
    // Return root trees for a given countryCode
    const roots = await this.locationRepo.find({
      where: { countryCode, parent: IsNull() },
      order: { name: 'ASC' },
    });

    const trees: Location[] = [];
    for (const root of roots) {
      trees.push(await treeRepo.findDescendantsTree(root));
    }
    return trees;
  }

  async create(payload: CreateLocationDto): Promise<Location> {
    const normalizedCountryCode = this.normalizeCountryCode(payload.countryCode);
    if (!normalizedCountryCode) {
      throw new BadRequestException('countryCode is required');
    }

    const chain = await this.getChain(normalizedCountryCode);

    let parent: Location | undefined;
    if (payload.parentId) {
      const foundParent = await this.locationRepo.findOne({ where: { id: payload.parentId } });
      if (!foundParent) throw new NotFoundException('Parent location not found');
      parent = foundParent;

      const parentCountry = this.normalizeCountryCode(parent.countryCode);
      if (parentCountry && parentCountry !== normalizedCountryCode) {
        throw new BadRequestException('countryCode must match parent countryCode');
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
        throw new BadRequestException(`Root locations must have type='${allowedRoot}'`);
      }
    }

    const entity = this.locationRepo.create({
      name: payload.name,
      type: payload.type,
      countryCode: normalizedCountryCode,
      code: payload.code,
      parent,
      metaJson: payload.metaJson ?? {},
    });

    return this.locationRepo.save(entity);
  }

  async update(id: string, payload: UpdateLocationDto): Promise<Location> {
    const existing = await this.locationRepo.findOne({ where: { id }, relations: ['parent'] });
    if (!existing) throw new NotFoundException('Location not found');

    const countryCode = this.normalizeCountryCode(payload.countryCode || existing.countryCode);
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

        const foundParent = await this.locationRepo.findOne({ where: { id: payload.parentId } });
        if (!foundParent) throw new NotFoundException('Parent location not found');

        // prevent cycles
        const treeRepo = this.dataSource.getTreeRepository(Location);
        const descendants = await treeRepo.findDescendants(existing);
        const descendantIds = new Set(descendants.map((d) => d.id));
        if (descendantIds.has(foundParent.id)) {
          throw new BadRequestException('Cannot move a location under its descendant');
        }

        const parentCountry = this.normalizeCountryCode(foundParent.countryCode);
        if (parentCountry && parentCountry !== countryCode) {
          throw new BadRequestException('countryCode must match parent countryCode');
        }

        const targetType = payload.type ?? existing.type;
        const allowed = this.allowedChildTypesFromChain(chain, foundParent.type);
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
        throw new BadRequestException(`Root locations must have type='${allowedRoot}'`);
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

    existing.countryCode = countryCode;
    if (typeof payload.name !== 'undefined') existing.name = payload.name;
    if (typeof payload.code !== 'undefined') existing.code = payload.code;
    if (typeof payload.type !== 'undefined') existing.type = payload.type;
    if (typeof payload.metaJson !== 'undefined') existing.metaJson = payload.metaJson ?? {};
    existing.parent = parent;

    return this.locationRepo.save(existing);
  }

  async delete(id: string, opts?: { force?: boolean }): Promise<{ deleted: boolean }> {
    const existing = await this.locationRepo.findOne({ where: { id } });
    if (!existing) throw new NotFoundException('Location not found');

    if (!opts?.force) {
      const children = await this.locationRepo.count({ where: { parent: { id } as any } });
      if (children > 0) {
        throw new BadRequestException('Location has children. Use force=true to delete recursively.');
      }
    }

    const res = await this.locationRepo.delete(id);
    return { deleted: (res.affected || 0) > 0 };
  }
}
