import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Brackets, Repository } from 'typeorm';
import { PriceList } from 'src/catalog/entities/price-list.entity';
import { CurrencyService } from 'src/currency/currency.service';
import { CreatePriceListDto } from './dto/create-price-list.dto';
import { UpdatePriceListDto } from './dto/update-price-list.dto';
import { FilterPriceListDto } from './dto/filter-price-list.dto';

@Injectable()
export class PricingService {
  constructor(
    @InjectRepository(PriceList)
    private readonly priceListRepo: Repository<PriceList>,
    private readonly currencyService: CurrencyService,
  ) {}

  async createPriceList(payload: CreatePriceListDto) {
    const existing = await this.priceListRepo.findOne({
      where: { code: payload.code },
    });
    if (existing) {
      throw new ConflictException(
        `PriceList with code '${payload.code}' already exists`,
      );
    }

    const currencyCode = await this.currencyService.assertExists(
      payload.currency,
    );

    const row = this.priceListRepo.create({
      code: payload.code,
      name: payload.name,
      currency: currencyCode,
      priority: payload.priority ?? 0,
      scope: payload.scope ?? {},
      status: (payload.status as any) ?? 'active',
      stackingPolicy: (payload.stackingPolicy as any) ?? 'EXCLUSIVE',
      matchPolicy: (payload.matchPolicy as any) ?? 'HIGHEST_PRIORITY',
      stopAfterMatch: payload.stopAfterMatch ?? true,
    });

    return this.priceListRepo.save(row);
  }

  async listPriceLists(filter: FilterPriceListDto) {
    const { getAll, limit, page } = filter;
    const skip = (page - 1) * limit;

    const qb = this.priceListRepo
      .createQueryBuilder('pl')
      .orderBy('pl.priority', 'DESC')
      .addOrderBy('pl.created_at', 'DESC');

    if (filter.search) {
      const q = `%${filter.search}%`;
      qb.andWhere(
        new Brackets((where) => {
          where
            .where('pl.code ILIKE :q', { q })
            .orWhere('pl.name ILIKE :q', { q });
        }),
      );
    }

    if (filter.currency) {
      const currencyCode = await this.currencyService.assertExists(
        filter.currency,
      );
      qb.andWhere('pl.currency_code = :currency', { currency: currencyCode });
    }

    if (filter.status) {
      qb.andWhere('pl.status = :status', { status: filter.status });
    }

    if (!getAll) {
      qb.skip(skip).take(limit);
    }

    const [data, total] = await qb.getManyAndCount();

    return { data, total, page, limit };
  }

  async getPriceList(id: string) {
    const row = await this.priceListRepo.findOne({ where: { id } });
    if (!row)
      throw new NotFoundException(`PriceList with ID '${id}' not found`);
    return row;
  }

  async updatePriceList(id: string, payload: UpdatePriceListDto) {
    const existing = await this.getPriceList(id);

    if (payload.code && payload.code !== existing.code) {
      const dup = await this.priceListRepo.findOne({
        where: { code: payload.code },
      });
      if (dup) {
        throw new ConflictException(
          `PriceList with code '${payload.code}' already exists`,
        );
      }
      existing.code = payload.code;
    }

    if (typeof payload.name !== 'undefined') existing.name = payload.name;
    if (typeof payload.currency !== 'undefined') {
      existing.currency = await this.currencyService.assertExists(
        payload.currency,
      );
    }
    if (typeof payload.priority !== 'undefined')
      existing.priority = payload.priority;
    if (typeof payload.scope !== 'undefined')
      existing.scope = payload.scope ?? {};
    if (typeof payload.status !== 'undefined')
      existing.status = payload.status as any;
    if (typeof payload.stackingPolicy !== 'undefined')
      existing.stackingPolicy = payload.stackingPolicy as any;
    if (typeof payload.matchPolicy !== 'undefined')
      existing.matchPolicy = payload.matchPolicy as any;
    if (typeof payload.stopAfterMatch !== 'undefined')
      existing.stopAfterMatch = payload.stopAfterMatch;

    return this.priceListRepo.save(existing);
  }

  async deletePriceList(id: string) {
    const existing = await this.getPriceList(id);
    await this.priceListRepo.remove(existing);
    return { deleted: true };
  }
}
