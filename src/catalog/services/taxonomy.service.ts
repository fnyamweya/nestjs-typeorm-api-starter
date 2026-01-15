import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Taxonomy } from '../entities/taxonomy.entity';
import { CreateTaxonomyDto } from '../dto/create-taxonomy.dto';
import { UpdateTaxonomyDto } from '../dto/update-taxonomy.dto';
import { AppCacheService } from 'src/common/cache/app-cache.service';
import { ShippingCatalogContextCacheIndexService } from 'src/common/cache/shipping-catalog-context-cache-index.service';
import { PublicTaxonomyDto } from '../dto/public/public-taxonomy.dto';

@Injectable()
export class TaxonomyService {
  constructor(
    @InjectRepository(Taxonomy)
    private readonly taxonomyRepository: Repository<Taxonomy>,
    private readonly cache: AppCacheService,
    private readonly shippingCatalogContextCacheIndex: ShippingCatalogContextCacheIndexService,
  ) {}

  async create(payload: CreateTaxonomyDto): Promise<Taxonomy> {
    const taxonomy = this.taxonomyRepository.create(payload);
    const saved = await this.taxonomyRepository.save(taxonomy);

    await this.cache.del('catalog:taxonomies:all');
    await this.cache.del(`catalog:taxonomies:${saved.id}`);
    return this.findOne(saved.id);
  }

  async findAll(): Promise<Taxonomy[]> {
    return this.cache.remember(
      'catalog:taxonomies:all',
      () => this.taxonomyRepository.find({ order: { createdAt: 'DESC' } }),
      { ttlSeconds: 300 },
    );
  }

  async findOne(id: string): Promise<Taxonomy> {
    const key = `catalog:taxonomies:${id}`;
    const taxonomy = await this.cache.remember(
      key,
      () => this.taxonomyRepository.findOne({ where: { id } }),
      { ttlSeconds: 300 },
    );

    if (!taxonomy) throw new NotFoundException('Taxonomy not found');
    return taxonomy;
  }

  async findAllPublic(): Promise<PublicTaxonomyDto[]> {
    return this.cache.remember(
      'public:catalog:taxonomies:all',
      async () => {
        const rows = await this.taxonomyRepository.find({
          where: { isActive: true },
          order: { createdAt: 'DESC' },
        });
        return rows.map((t) => ({
          id: t.id,
          code: t.code,
          name: t.name,
          description: t.description,
          icon: t.icon,
          avatarUrl: t.avatarUrl,
          isDefault: t.isDefault,
        }));
      },
      { ttlSeconds: 300 },
    );
  }

  async findOnePublic(id: string): Promise<PublicTaxonomyDto> {
    const key = `public:catalog:taxonomies:${id}`;
    const taxonomy = await this.cache.remember(
      key,
      () => this.taxonomyRepository.findOne({ where: { id, isActive: true } }),
      { ttlSeconds: 300 },
    );

    if (!taxonomy) throw new NotFoundException('Taxonomy not found');
    return {
      id: taxonomy.id,
      code: taxonomy.code,
      name: taxonomy.name,
      description: taxonomy.description,
      icon: taxonomy.icon,
      avatarUrl: taxonomy.avatarUrl,
      isDefault: taxonomy.isDefault,
    };
  }

  async update(id: string, payload: UpdateTaxonomyDto): Promise<Taxonomy> {
    const taxonomy = await this.taxonomyRepository.findOne({ where: { id } });
    if (!taxonomy) throw new NotFoundException('Taxonomy not found');

    Object.assign(taxonomy, payload);
    await this.taxonomyRepository.save(taxonomy);

    await this.cache.del('catalog:taxonomies:all');
    await this.cache.del(`catalog:taxonomies:${id}`);
    await this.shippingCatalogContextCacheIndex.invalidateByTaxonomyIds([id]);
    return this.findOne(id);
  }

  async remove(id: string): Promise<void> {
    const taxonomy = await this.taxonomyRepository.findOne({ where: { id } });
    if (!taxonomy) throw new NotFoundException('Taxonomy not found');

    await this.taxonomyRepository.remove(taxonomy);

    await this.cache.del('catalog:taxonomies:all');
    await this.cache.del(`catalog:taxonomies:${id}`);
    await this.shippingCatalogContextCacheIndex.invalidateByTaxonomyIds([id]);
  }
}
