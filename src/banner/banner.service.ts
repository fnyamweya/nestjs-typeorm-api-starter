import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Banner } from './entities/banner.entity';
import { CreateBannerDto } from './dto/create-banner.dto';
import { UpdateBannerDto } from './dto/update-banner.dto';
import { FilterBannerDto } from './dto/filter-banner.dto';

@Injectable()
export class BannerService {
  constructor(
    @InjectRepository(Banner)
    private readonly repo: Repository<Banner>,
  ) {}

  private validateCreative(creative: Record<string, unknown>) {
    const kind = String((creative as any)?.kind ?? '').trim();
    if (!kind) {
      throw new BadRequestException(
        "creative.kind is required (e.g. 'image' or 'color')",
      );
    }

    if (kind === 'image') {
      const imageKey = (creative as any)?.imageKey;
      const imageUrl = (creative as any)?.imageUrl;
      if (!imageKey && !imageUrl) {
        throw new BadRequestException(
          "For creative.kind='image', provide creative.imageKey or creative.imageUrl",
        );
      }
    }

    if (kind === 'color') {
      const bg = (creative as any)?.backgroundColor;
      if (!bg) {
        throw new BadRequestException(
          "For creative.kind='color', provide creative.backgroundColor",
        );
      }
    }
  }

  private normalizePlacements(placements: Array<Record<string, unknown>>) {
    const normalized = (placements || []).map((p) => ({
      ...p,
      page:
        typeof (p as any).page === 'string'
          ? String((p as any).page).trim()
          : (p as any).page,
      section:
        typeof (p as any).section === 'string'
          ? String((p as any).section).trim()
          : (p as any).section,
    }));

    if (!normalized.length) {
      throw new BadRequestException('placements must be a non-empty array');
    }

    for (const item of normalized) {
      if (!item.page)
        throw new BadRequestException('placements[].page is required');
    }

    return normalized;
  }

  private normalizeTargets(targets?: Array<Record<string, unknown>>) {
    const normalized = (targets || []).map((t) => ({
      ...t,
      kind:
        typeof (t as any).kind === 'string'
          ? String((t as any).kind).trim()
          : (t as any).kind,
    }));

    for (const item of normalized) {
      if (!item.kind)
        throw new BadRequestException('targets[].kind is required');
    }

    return normalized;
  }

  async create(payload: CreateBannerDto): Promise<Banner> {
    this.validateCreative(payload.creative);

    const row = this.repo.create({
      name: payload.name,
      isActive: payload.isActive ?? true,
      startsAt: payload.startsAt ? new Date(payload.startsAt) : null,
      endsAt: payload.endsAt ? new Date(payload.endsAt) : null,
      priority: payload.priority ?? 0,
      creativeJson: payload.creative,
      placementsJson: this.normalizePlacements(payload.placements as any),
      targetsJson: this.normalizeTargets(payload.targets as any),
      metaJson: payload.meta ?? {},
    });

    return this.repo.save(row);
  }

  async findAll(filter: FilterBannerDto, opts?: { publicOnly?: boolean }) {
    const { getAll, limit, page } = filter;
    const skip = (page - 1) * limit;

    const qb = this.repo
      .createQueryBuilder('b')
      .orderBy('b.priority', 'DESC')
      .addOrderBy('b.created_at', 'DESC');

    // search
    if (filter.search) {
      qb.andWhere('b.name ILIKE :q', { q: `%${filter.search}%` });
    }

    if (typeof filter.isActive !== 'undefined') {
      qb.andWhere('b.is_active = :isActive', { isActive: filter.isActive });
    }

    // dynamic JSONB filters
    if (filter.placementPage) {
      qb.andWhere('b.placements_json @> :placementsPage', {
        placementsPage: JSON.stringify([{ page: filter.placementPage }]),
      });
    }

    if (filter.placementSection) {
      qb.andWhere('b.placements_json @> :placementsSection', {
        placementsSection: JSON.stringify([
          { section: filter.placementSection },
        ]),
      });
    }

    if (filter.targetKind) {
      qb.andWhere('b.targets_json @> :targetsKind', {
        targetsKind: JSON.stringify([{ kind: filter.targetKind }]),
      });
    }

    if (filter.targetRefId) {
      qb.andWhere('b.targets_json @> :targetsRefId', {
        targetsRefId: JSON.stringify([{ refId: filter.targetRefId }]),
      });
    }

    const onlyCurrentlyActive = opts?.publicOnly
      ? true
      : (filter.onlyCurrentlyActive ?? false);

    if (onlyCurrentlyActive) {
      const now = new Date();
      qb.andWhere('b.is_active = true');
      qb.andWhere('(b.starts_at IS NULL OR b.starts_at <= :now)', { now });
      qb.andWhere('(b.ends_at IS NULL OR b.ends_at >= :now)', { now });
    }

    if (!getAll) {
      qb.skip(skip).take(limit);
    }

    const [data, total] = await qb.getManyAndCount();

    return { data, total, page, limit };
  }

  async findOne(id: string): Promise<Banner> {
    const row = await this.repo.findOne({ where: { id } });
    if (!row) throw new NotFoundException(`Banner with ID '${id}' not found`);
    return row;
  }

  async update(id: string, payload: UpdateBannerDto): Promise<Banner> {
    const existing = await this.findOne(id);

    if (payload.creative) {
      this.validateCreative(payload.creative);
      existing.creativeJson = payload.creative;
    }

    if (typeof payload.name !== 'undefined') existing.name = payload.name;
    if (typeof payload.isActive !== 'undefined')
      existing.isActive = payload.isActive;
    if (typeof payload.startsAt !== 'undefined')
      existing.startsAt = payload.startsAt ? new Date(payload.startsAt) : null;
    if (typeof payload.endsAt !== 'undefined')
      existing.endsAt = payload.endsAt ? new Date(payload.endsAt) : null;
    if (typeof payload.priority !== 'undefined')
      existing.priority = payload.priority;

    if (typeof payload.placements !== 'undefined') {
      existing.placementsJson = this.normalizePlacements(
        payload.placements as any,
      );
    }

    if (typeof payload.targets !== 'undefined') {
      existing.targetsJson = this.normalizeTargets(payload.targets as any);
    }

    if (typeof payload.meta !== 'undefined') {
      existing.metaJson = payload.meta ?? {};
    }

    return this.repo.save(existing);
  }

  async remove(id: string) {
    const existing = await this.findOne(id);
    await this.repo.remove(existing);
    return { deleted: true };
  }
}
