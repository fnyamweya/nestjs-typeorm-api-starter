import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ILike, Repository } from 'typeorm';
import { PaymentProvider } from '../entities/payment-provider.entity';
import { CreatePaymentProviderDto } from '../dto/create-payment-provider.dto';
import { UpdatePaymentProviderDto } from '../dto/update-payment-provider.dto';
import { ListPaymentProvidersDto } from '../dto/list-payment-providers.dto';

@Injectable()
export class PaymentProviderService {
  constructor(
    @InjectRepository(PaymentProvider)
    private readonly providerRepo: Repository<PaymentProvider>,
  ) {}

  private normalizeCode(code: string): string {
    return (code || '').trim().toUpperCase();
  }

  async list(params: ListPaymentProvidersDto): Promise<PaymentProvider[]> {
    const where: any = {
      ...(typeof params.isActive === 'boolean'
        ? { isActive: params.isActive }
        : {}),
    };

    if (params.q) {
      return this.providerRepo.find({
        where: [
          { ...where, code: ILike(`%${params.q}%`) },
          { ...where, name: ILike(`%${params.q}%`) },
        ],
        order: { name: 'ASC' },
      });
    }

    return this.providerRepo.find({ where, order: { name: 'ASC' } });
  }

  async getById(id: string): Promise<PaymentProvider> {
    const row = await this.providerRepo.findOne({ where: { id } });
    if (!row) throw new NotFoundException('Payment provider not found');
    return row;
  }

  async getByCode(code: string): Promise<PaymentProvider | null> {
    const normalized = this.normalizeCode(code);
    if (!normalized) return null;
    return this.providerRepo.findOne({ where: { code: normalized } });
  }

  async create(payload: CreatePaymentProviderDto): Promise<PaymentProvider> {
    const code = this.normalizeCode(payload.code);
    if (!code) throw new BadRequestException('code is required');

    const existing = await this.providerRepo.findOne({ where: { code } });
    if (existing)
      throw new BadRequestException('Payment provider code already exists');

    const entity = this.providerRepo.create({
      code,
      name: payload.name,
      description: payload.description,
      isActive: payload.isActive ?? true,
      configJson: payload.configJson ?? {},
      metadata: payload.metadata ?? {},
    });

    return this.providerRepo.save(entity);
  }

  async update(
    id: string,
    payload: UpdatePaymentProviderDto,
  ): Promise<PaymentProvider> {
    const existing = await this.providerRepo.findOne({ where: { id } });
    if (!existing) throw new NotFoundException('Payment provider not found');

    if (typeof payload.code !== 'undefined') {
      const code = this.normalizeCode(payload.code);
      if (!code) throw new BadRequestException('code is invalid');
      const conflict = await this.providerRepo.findOne({ where: { code } });
      if (conflict && conflict.id !== existing.id) {
        throw new BadRequestException('Payment provider code already exists');
      }
      existing.code = code;
    }

    if (typeof payload.name !== 'undefined') existing.name = payload.name;
    if (typeof payload.description !== 'undefined')
      existing.description = payload.description;
    if (typeof payload.isActive !== 'undefined')
      existing.isActive = payload.isActive;
    if (typeof payload.configJson !== 'undefined')
      existing.configJson = payload.configJson ?? {};
    if (typeof payload.metadata !== 'undefined')
      existing.metadata = payload.metadata ?? {};

    return this.providerRepo.save(existing);
  }

  async delete(id: string): Promise<{ deleted: boolean }> {
    const existing = await this.providerRepo.findOne({ where: { id } });
    if (!existing) throw new NotFoundException('Payment provider not found');

    const res = await this.providerRepo.delete(id);
    return { deleted: (res.affected || 0) > 0 };
  }
}
