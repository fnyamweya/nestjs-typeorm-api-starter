import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Channel } from '../entities/channel.entity';

type SeedChannel = {
  code: string;
  name: string;
  description?: string;
  isActive?: boolean;
  configJson?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
};

@Injectable()
export class ChannelsSeeder {
  constructor(
    @InjectRepository(Channel)
    private readonly channelRepo: Repository<Channel>,
  ) {}

  private normalizeCode(code: string): string {
    return (code || '').trim().toUpperCase();
  }

  private defaultChannels(): SeedChannel[] {
    return [
      {
        code: 'WEB',
        name: 'Web Store',
        description: 'Primary web storefront channel',
        isActive: true,
        metadata: { kind: 'storefront' },
      },
      {
        code: 'MOBILE',
        name: 'Mobile App',
        description: 'Mobile storefront channel',
        isActive: true,
        metadata: { kind: 'storefront' },
      },
      {
        code: 'WHATSAPP',
        name: 'WhatsApp',
        description: 'WhatsApp conversational commerce channel',
        isActive: true,
        metadata: { kind: 'storefront' },
      },
    ];
  }

  private async upsert(channel: SeedChannel): Promise<void> {
    const code = this.normalizeCode(channel.code);
    if (!code) return;

    const existing = await this.channelRepo.findOne({ where: { code } });
    if (!existing) {
      await this.channelRepo.save(
        this.channelRepo.create({
          code,
          name: channel.name,
          description: channel.description,
          isActive: channel.isActive ?? true,
          configJson: channel.configJson ?? {},
          metadata: channel.metadata ?? {},
        }),
      );
      return;
    }

    // Keep idempotent but allow evolving defaults
    existing.name = channel.name;
    existing.description = channel.description;
    existing.isActive = channel.isActive ?? existing.isActive;
    if (typeof channel.configJson !== 'undefined')
      existing.configJson = channel.configJson ?? {};
    if (typeof channel.metadata !== 'undefined')
      existing.metadata = channel.metadata ?? {};

    await this.channelRepo.save(existing);
  }

  async seed(): Promise<void> {
    for (const channel of this.defaultChannels()) {
      await this.upsert(channel);
    }
  }
}
