import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CustomerTier } from '../entities/customer-tier.entity';

@Injectable()
export class CustomerTierSeeder {
  constructor(
    @InjectRepository(CustomerTier)
    private readonly tierRepository: Repository<CustomerTier>,
  ) {}

  async seed(): Promise<void> {
    const defaults: Array<
      Pick<
        CustomerTier,
        'code' | 'name' | 'priority' | 'isActive' | 'configJson' | 'metadata'
      >
    > = [
      {
        code: 'BASE',
        name: 'Base',
        priority: 0,
        isActive: true,
        configJson: {},
        metadata: {},
      },
    ];

    for (const t of defaults) {
      const exists = await this.tierRepository.findOne({
        where: { code: t.code } as any,
      });
      if (exists) continue;
      await this.tierRepository.save(this.tierRepository.create(t as any));
    }
  }
}
