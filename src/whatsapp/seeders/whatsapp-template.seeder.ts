import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { WhatsappTemplate } from '../entities/whatsapp-template.entity';

type SeedTemplate = Pick<
  WhatsappTemplate,
  | 'name'
  | 'language'
  | 'category'
  | 'status'
  | 'isActive'
  | 'componentsJson'
  | 'defaultComponentsJson'
  | 'metaJson'
>;

@Injectable()
export class WhatsappTemplateSeeder {
  constructor(
    @InjectRepository(WhatsappTemplate)
    private readonly templateRepository: Repository<WhatsappTemplate>,
  ) {}

  private buildSeedTemplates(): SeedTemplate[] {
    return [
      {
        name: 'order_success',
        language: 'en_US',
        category: 'UTILITY',
        status: 'draft',
        isActive: true,
        componentsJson: [
          {
            type: 'BODY',
            text: 'Hi {{1}}, your order {{2}} was placed successfully. Total: {{3}}. Track: {{4}}',
          },
        ],
        defaultComponentsJson: [
          {
            type: 'body',
            parameters: [
              { type: 'text', text: 'Customer' },
              { type: 'text', text: 'ORDER-12345' },
              { type: 'text', text: 'KES 1,250' },
              { type: 'text', text: 'https://example.com/orders/ORDER-12345' },
            ],
          },
        ],
        metaJson: {
          seededBy: 'WhatsappTemplateSeeder',
          seedKey: 'order_success',
          seedVersion: 1,
          description: 'Sent when an order is successfully placed',
        },
      },
      {
        name: 'customer_registration_success',
        language: 'en_US',
        category: 'UTILITY',
        status: 'draft',
        isActive: true,
        componentsJson: [
          {
            type: 'BODY',
            text: 'Welcome {{1}}! Your registration was successful. You can now sign in and start shopping.',
          },
        ],
        defaultComponentsJson: [
          {
            type: 'body',
            parameters: [{ type: 'text', text: 'Customer' }],
          },
        ],
        metaJson: {
          seededBy: 'WhatsappTemplateSeeder',
          seedKey: 'customer_registration_success',
          seedVersion: 1,
          description:
            'Sent after customer registration completes successfully',
        },
      },
    ];
  }

  async seed() {
    const templates = this.buildSeedTemplates();

    for (const seed of templates) {
      const existing = await this.templateRepository.findOne({
        where: { name: seed.name },
      });

      if (!existing) {
        const created = this.templateRepository.create(seed);
        await this.templateRepository.save(created);
        console.log(`Created WhatsApp template: ${seed.name}`);
        continue;
      }

      const existingMeta = existing.metaJson ?? {};
      const seededBy = existingMeta.seededBy;
      const seedKey = existingMeta.seedKey;

      // Avoid overwriting templates that were manually created/maintained.
      if (
        seededBy &&
        (seededBy !== 'WhatsappTemplateSeeder' ||
          seedKey !== seed.metaJson.seedKey)
      ) {
        console.log(
          `Skipping WhatsApp template (not seeded by us): ${seed.name}`,
        );
        continue;
      }

      Object.assign(existing, {
        language: seed.language,
        category: seed.category,
        status: seed.status,
        isActive: seed.isActive,
        componentsJson: seed.componentsJson,
        defaultComponentsJson: seed.defaultComponentsJson,
        metaJson: {
          ...existingMeta,
          ...seed.metaJson,
        },
      });

      await this.templateRepository.save(existing);
      console.log(`Upserted WhatsApp template: ${seed.name}`);
    }
  }
}
