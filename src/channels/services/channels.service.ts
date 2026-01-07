import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ILike, Repository } from 'typeorm';
import { Channel } from '../entities/channel.entity';
import { CreateChannelDto } from '../dto/create-channel.dto';
import { UpdateChannelDto } from '../dto/update-channel.dto';
import { ListChannelsDto } from '../dto/list-channels.dto';
import { PublicListChannelsDto } from '../dto/public-list-channels.dto';
import { PublicChannelDto } from '../dto/public-channel.dto';
import { CurrencyService } from 'src/currency/currency.service';

@Injectable()
export class ChannelsService {
  constructor(
    @InjectRepository(Channel)
    private readonly channelRepo: Repository<Channel>,
    private readonly currencyService: CurrencyService,
  ) {}

  private normalizeCode(code: string): string {
    return (code || '').trim().toUpperCase();
  }

  private async normalizeAndValidateConfigCurrency(
    configJson: Record<string, unknown> | undefined,
  ): Promise<Record<string, unknown> | undefined> {
    if (!configJson) return configJson;
    const raw = (configJson as any).currencyCode;
    if (typeof raw === 'undefined') return configJson;

    const currencyCode = await this.currencyService.assertExists(raw);
    return { ...configJson, currencyCode };
  }

  async list(params: ListChannelsDto): Promise<Channel[]> {
    const where: any = {
      ...(typeof params.isActive === 'boolean'
        ? { isActive: params.isActive }
        : {}),
    };

    if (params.q) {
      // OR search: TypeORM supports array of where objects
      return this.channelRepo.find({
        where: [
          { ...where, code: ILike(`%${params.q}%`) },
          { ...where, name: ILike(`%${params.q}%`) },
        ],
        order: { name: 'ASC' },
      });
    }

    return this.channelRepo.find({ where, order: { name: 'ASC' } });
  }

  async listPublic(params: PublicListChannelsDto): Promise<PublicChannelDto[]> {
    const baseWhere: any = { isActive: true };

    let rows: Channel[];
    if (params.q) {
      rows = await this.channelRepo.find({
        where: [
          { ...baseWhere, code: ILike(`%${params.q}%`) },
          { ...baseWhere, name: ILike(`%${params.q}%`) },
        ],
        order: { name: 'ASC' },
      });
    } else {
      rows = await this.channelRepo.find({
        where: baseWhere,
        order: { name: 'ASC' },
      });
    }

    return rows.map((row) => ({
      id: row.id,
      code: row.code,
      name: row.name,
      description: row.description,
    }));
  }

  async getPublicByCode(code: string): Promise<PublicChannelDto> {
    const normalized = this.normalizeCode(code);
    if (!normalized) throw new NotFoundException('Channel not found');

    const row = await this.channelRepo.findOne({
      where: { code: normalized, isActive: true },
    });
    if (!row) throw new NotFoundException('Channel not found');

    return {
      id: row.id,
      code: row.code,
      name: row.name,
      description: row.description,
    };
  }

  async getById(id: string): Promise<Channel> {
    const row = await this.channelRepo.findOne({ where: { id } });
    if (!row) throw new NotFoundException('Channel not found');
    return row;
  }

  async getByCode(code: string): Promise<Channel | null> {
    const normalized = this.normalizeCode(code);
    if (!normalized) return null;
    return this.channelRepo.findOne({ where: { code: normalized } });
  }

  async create(payload: CreateChannelDto): Promise<Channel> {
    const code = this.normalizeCode(payload.code);
    if (!code) throw new BadRequestException('code is required');

    const existing = await this.channelRepo.findOne({ where: { code } });
    if (existing) throw new BadRequestException('Channel code already exists');

    const entity = this.channelRepo.create({
      code,
      name: payload.name,
      description: payload.description,
      isActive: payload.isActive ?? true,
      configJson:
        (await this.normalizeAndValidateConfigCurrency(payload.configJson)) ??
        {},
      metadata: payload.metadata ?? {},
    });

    return this.channelRepo.save(entity);
  }

  async update(id: string, payload: UpdateChannelDto): Promise<Channel> {
    const existing = await this.channelRepo.findOne({ where: { id } });
    if (!existing) throw new NotFoundException('Channel not found');

    if (typeof payload.code !== 'undefined') {
      const code = this.normalizeCode(payload.code);
      if (!code) throw new BadRequestException('code is invalid');
      const conflict = await this.channelRepo.findOne({ where: { code } });
      if (conflict && conflict.id !== existing.id) {
        throw new BadRequestException('Channel code already exists');
      }
      existing.code = code;
    }

    if (typeof payload.name !== 'undefined') existing.name = payload.name;
    if (typeof payload.description !== 'undefined')
      existing.description = payload.description;
    if (typeof payload.isActive !== 'undefined')
      existing.isActive = payload.isActive;
    if (typeof payload.configJson !== 'undefined') {
      existing.configJson =
        (await this.normalizeAndValidateConfigCurrency(payload.configJson)) ??
        {};
    }
    if (typeof payload.metadata !== 'undefined')
      existing.metadata = payload.metadata ?? {};

    return this.channelRepo.save(existing);
  }

  async delete(id: string): Promise<{ deleted: boolean }> {
    const existing = await this.channelRepo.findOne({ where: { id } });
    if (!existing) throw new NotFoundException('Channel not found');

    const res = await this.channelRepo.delete(id);
    return { deleted: (res.affected || 0) > 0 };
  }
}
