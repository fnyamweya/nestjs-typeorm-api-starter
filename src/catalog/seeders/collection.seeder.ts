import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Collection, CollectionRuleType } from '../entities/collection.entity';

@Injectable()
export class CollectionSeeder {
  private readonly logger = new Logger(CollectionSeeder.name);

  constructor(
    @InjectRepository(Collection)
    private readonly collectionRepository: Repository<Collection>,
  ) {}

  async seed() {
    await this.ensureCollection({
      title: 'Deal Of The Day',
      slug: 'deal-of-the-day',
      type: 'deal-of-the-day',
      ruleType: CollectionRuleType.STATIC,
      rulePayload: {},
      priority: 100,
      isActive: true,
    });

    await this.ensureCollection({
      title: 'New Arrivals',
      slug: 'new-arrivals',
      type: 'new-arrivals',
      ruleType: CollectionRuleType.QUERY,
      rulePayload: { sort: 'newest', limit: 12 },
      priority: 90,
      isActive: true,
    });

    this.logger.log('Seeded default collections (deal-of-the-day, new-arrivals)');
  }

  private async ensureCollection(input: {
    title: string;
    slug: string;
    type: string;
    ruleType: CollectionRuleType;
    rulePayload: Record<string, unknown>;
    priority: number;
    isActive: boolean;
  }) {
    const existing = await this.collectionRepository.findOne({
      where: { slug: input.slug },
    });

    if (existing) {
      Object.assign(existing, {
        title: input.title,
        type: input.type,
        ruleType: input.ruleType,
        rulePayload: input.rulePayload as any,
        priority: input.priority,
        isActive: input.isActive,
      });
      await this.collectionRepository.save(existing);
      return existing;
    }

    const collection = this.collectionRepository.create({
      title: input.title,
      slug: input.slug,
      type: input.type,
      ruleType: input.ruleType,
      rulePayload: input.rulePayload as any,
      priority: input.priority,
      isActive: input.isActive,
    });

    return this.collectionRepository.save(collection);
  }
}
