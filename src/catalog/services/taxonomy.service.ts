import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Taxonomy } from '../entities/taxonomy.entity';
import { CreateTaxonomyDto } from '../dto/create-taxonomy.dto';
import { UpdateTaxonomyDto } from '../dto/update-taxonomy.dto';

@Injectable()
export class TaxonomyService {
  constructor(
    @InjectRepository(Taxonomy)
    private readonly taxonomyRepository: Repository<Taxonomy>,
  ) {}

  async create(payload: CreateTaxonomyDto): Promise<Taxonomy> {
    const taxonomy = this.taxonomyRepository.create(payload);
    return this.taxonomyRepository.save(taxonomy);
  }

  async findAll(): Promise<Taxonomy[]> {
    return this.taxonomyRepository.find({ order: { createdAt: 'DESC' } });
  }

  async findOne(id: string): Promise<Taxonomy> {
    const taxonomy = await this.taxonomyRepository.findOne({ where: { id } });
    if (!taxonomy) {
      throw new NotFoundException('Taxonomy not found');
    }
    return taxonomy;
  }

  async update(id: string, payload: UpdateTaxonomyDto): Promise<Taxonomy> {
    const taxonomy = await this.findOne(id);
    Object.assign(taxonomy, payload);
    return this.taxonomyRepository.save(taxonomy);
  }

  async remove(id: string): Promise<void> {
    const taxonomy = await this.findOne(id);
    await this.taxonomyRepository.remove(taxonomy);
  }
}
