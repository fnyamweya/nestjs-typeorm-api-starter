import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import slugify from 'slugify';
import { Brand } from '../entities/brand.entity';
import { CreateBrandDto } from '../dto/create-brand.dto';
import { UpdateBrandDto } from '../dto/update-brand.dto';
import { FilterBrandDto } from '../dto/filter-brand.dto';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import {
  cacheKeyFromParts,
  cacheKeyHash,
} from 'src/common/cache/cache-key.util';
import { PublicBrandDto } from '../dto/public/public-brand.dto';
import { PublicListBrandsDto } from '../dto/public/public-list-brands.dto';

export interface PaginatedBrands {
  data: Brand[];
  total: number;
  page: number;
  limit: number;
}

@Injectable()
export class BrandService {
  constructor(
    @InjectRepository(Brand)
    private readonly brandRepository: Repository<Brand>,
    private readonly cache: AppCacheService,
  ) {}

  async create(payload: CreateBrandDto): Promise<Brand> {
    const slug = await this.generateUniqueSlug(payload.name);

    const brand = this.brandRepository.create({
      name: payload.name,
      slug,
      description: payload.description,
      logoUrl: payload.logoUrl,
      icon: payload.icon,
      avatarUrl: payload.avatarUrl,
      websiteUrl: payload.websiteUrl,
      isActive: payload.isActive ?? true,
      metaJson: payload.metaJson ?? {},
    });

    const saved = await this.brandRepository.save(brand);
    await this.cache.delByPrefix('catalog:brands:list:');
    await this.cache.del(`catalog:brands:${saved.id}`);
    return this.findOne(saved.id);
  }

  async findAll(filters: FilterBrandDto): Promise<PaginatedBrands> {
    const page = filters.page ?? 1;
    const limit = filters.limit ?? 10;

    const rawKey = cacheKeyFromParts('catalog', 'brands', 'list', {
      page,
      limit,
      isActive: filters.isActive,
      search: filters.search,
    });
    const key = `catalog:brands:list:${cacheKeyHash(rawKey)}`;

    return this.cache.remember(
      key,
      async () => {
        const qb = this.brandRepository
          .createQueryBuilder('brand')
          .skip((page - 1) * limit)
          .take(limit)
          .orderBy('brand.createdAt', 'DESC');

        if (filters.isActive !== undefined) {
          qb.andWhere('brand.is_active = :isActive', {
            isActive: filters.isActive,
          });
        }

        if (filters.search) {
          qb.andWhere(
            '(brand.name ILIKE :search OR brand.slug ILIKE :search)',
            {
              search: `%${filters.search}%`,
            },
          );
        }

        const [data, total] = await qb.getManyAndCount();
        return { data, total, page, limit };
      },
      { ttlSeconds: 60 },
    );
  }

  async findOne(id: string): Promise<Brand> {
    const key = `catalog:brands:${id}`;
    const brand = await this.cache.remember(
      key,
      () =>
        this.brandRepository.findOne({
          where: { id },
        }),
      { ttlSeconds: 300 },
    );

    if (!brand) throw new NotFoundException('Brand not found');
    return brand;
  }

  async findAllPublic(filters: PublicListBrandsDto): Promise<{
    data: PublicBrandDto[];
    total: number;
    page: number;
    limit: number;
  }> {
    const page = filters.page ?? 1;
    const limit = filters.limit ?? 10;

    const rawKey = cacheKeyFromParts('public', 'catalog', 'brands', 'list', {
      page,
      limit,
      search: filters.search,
    });
    const key = `public:catalog:brands:list:${cacheKeyHash(rawKey)}`;

    return this.cache.remember(
      key,
      async () => {
        const qb = this.brandRepository
          .createQueryBuilder('brand')
          .where('brand.is_active = true')
          .skip((page - 1) * limit)
          .take(limit)
          .orderBy('brand.createdAt', 'DESC');

        if (filters.search) {
          qb.andWhere(
            '(brand.name ILIKE :search OR brand.slug ILIKE :search)',
            {
              search: `%${filters.search}%`,
            },
          );
        }

        const [data, total] = await qb.getManyAndCount();
        return {
          data: data.map((b) => ({
            id: b.id,
            name: b.name,
            slug: b.slug,
            description: b.description,
            logoUrl: b.logoUrl,
            icon: b.icon,
            avatarUrl: b.avatarUrl,
            websiteUrl: b.websiteUrl,
          })),
          total,
          page,
          limit,
        };
      },
      { ttlSeconds: 60 },
    );
  }

  async findOnePublic(id: string): Promise<PublicBrandDto> {
    const rawKey = cacheKeyFromParts('public', 'catalog', 'brands', 'one', {
      id,
    });
    const key = `public:catalog:brands:${cacheKeyHash(rawKey)}`;

    const brand = await this.cache.remember(
      key,
      () => this.brandRepository.findOne({ where: { id, isActive: true } }),
      { ttlSeconds: 300 },
    );

    if (!brand) throw new NotFoundException('Brand not found');

    return {
      id: brand.id,
      name: brand.name,
      slug: brand.slug,
      description: brand.description,
      logoUrl: brand.logoUrl,
      icon: brand.icon,
      avatarUrl: brand.avatarUrl,
      websiteUrl: brand.websiteUrl,
    };
  }

  async update(id: string, payload: UpdateBrandDto): Promise<Brand> {
    const brand = await this.findOneEntityOrThrow(id);

    const nextName = payload.name ?? brand.name;
    const nameChanged =
      payload.name !== undefined && payload.name !== brand.name;

    Object.assign(brand, {
      name: nextName,
      description: payload.description ?? brand.description,
      logoUrl: payload.logoUrl ?? brand.logoUrl,
      icon: payload.icon ?? brand.icon,
      avatarUrl: payload.avatarUrl ?? brand.avatarUrl,
      websiteUrl: payload.websiteUrl ?? brand.websiteUrl,
      isActive: payload.isActive ?? brand.isActive,
      metaJson: payload.metaJson ?? brand.metaJson,
    });

    if (nameChanged) {
      brand.slug = await this.generateUniqueSlug(nextName, brand.id);
    }

    await this.brandRepository.save(brand);

    await this.cache.delByPrefix('catalog:brands:list:');
    await this.cache.del(`catalog:brands:${id}`);
    return this.findOne(id);
  }

  async remove(id: string): Promise<void> {
    const brand = await this.findOneEntityOrThrow(id);
    await this.brandRepository.remove(brand);

    await this.cache.delByPrefix('catalog:brands:list:');
    await this.cache.del(`catalog:brands:${id}`);
  }

  private async findOneEntityOrThrow(id: string): Promise<Brand> {
    const brand = await this.brandRepository.findOne({ where: { id } });
    if (!brand) throw new NotFoundException('Brand not found');
    return brand;
  }

  private async generateUniqueSlug(
    name: string,
    excludeId?: string,
  ): Promise<string> {
    const base = slugify(name, { lower: true, strict: true, trim: true });
    const baseSlug = base.length ? base : 'brand';

    let candidate = baseSlug;
    let suffix = 2;

    // keep it simple and safe: loop until we find a free slug
    // (brands count is expected to be relatively small)

    while (true) {
      const existing = await this.brandRepository.findOne({
        where: { slug: candidate },
      });
      if (!existing || existing.id === excludeId) return candidate;
      candidate = `${baseSlug}-${suffix}`;
      suffix += 1;
    }
  }
}
