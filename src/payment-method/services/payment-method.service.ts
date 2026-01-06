import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ILike, Repository } from 'typeorm';
import { PaymentMethod } from '../entities/payment-method.entity';
import { CreatePaymentMethodDto } from '../dto/create-payment-method.dto';
import { UpdatePaymentMethodDto } from '../dto/update-payment-method.dto';
import { ListPaymentMethodsDto } from '../dto/list-payment-methods.dto';

@Injectable()
export class PaymentMethodService {
  constructor(
    @InjectRepository(PaymentMethod)
    private readonly methodRepo: Repository<PaymentMethod>,
  ) {}

  private normalizeCode(code: string): string {
    return (code || '').trim().toUpperCase();
  }

  private normalizeChannelCodes(channels: string[] | undefined): string[] | undefined {
    if (!channels) return undefined;
    return Array.from(
      new Set(
        channels
          .map((c) => String(c ?? '').trim().toUpperCase())
          .filter(Boolean),
      ),
    );
  }

  async list(params: ListPaymentMethodsDto): Promise<PaymentMethod[]> {
    const where: any = {
      ...(typeof params.isActive === 'boolean' ? { isActive: params.isActive } : {}),
      ...(params.providerId ? { providerId: params.providerId } : {}),
    };

    if (params.channel) {
      const channel = this.normalizeCode(params.channel);
      if (channel) {
        where.channels = channel;
      }
    }

    if (params.q) {
      return this.methodRepo.find({
        where: [
          { ...where, code: ILike(`%${params.q}%`) },
          { ...where, name: ILike(`%${params.q}%`) },
        ],
        order: { name: 'ASC' },
      });
    }

    return this.methodRepo.find({ where, order: { name: 'ASC' } });
  }

  async getById(id: string): Promise<PaymentMethod> {
    const row = await this.methodRepo.findOne({ where: { id } });
    if (!row) throw new NotFoundException('Payment method not found');
    return row;
  }

  async getByCode(code: string): Promise<PaymentMethod | null> {
    const normalized = this.normalizeCode(code);
    if (!normalized) return null;
    return this.methodRepo.findOne({ where: { code: normalized } });
  }

  async create(payload: CreatePaymentMethodDto): Promise<PaymentMethod> {
    const code = this.normalizeCode(payload.code);
    if (!code) throw new BadRequestException('code is required');

    const existing = await this.methodRepo.findOne({ where: { code } });
    if (existing) throw new BadRequestException('Payment method code already exists');

    const entity = this.methodRepo.create({
      code,
      providerId: payload.providerId,
      name: payload.name,
      description: payload.description,
      isActive: payload.isActive ?? true,
      channels: this.normalizeChannelCodes(payload.channels) ?? [],
      configJson: payload.configJson ?? {},
      metadata: payload.metadata ?? {},
    });

    return this.methodRepo.save(entity);
  }

  async update(id: string, payload: UpdatePaymentMethodDto): Promise<PaymentMethod> {
    const existing = await this.methodRepo.findOne({ where: { id } });
    if (!existing) throw new NotFoundException('Payment method not found');

    if (typeof payload.code !== 'undefined') {
      const code = this.normalizeCode(payload.code);
      if (!code) throw new BadRequestException('code is invalid');
      const conflict = await this.methodRepo.findOne({ where: { code } });
      if (conflict && conflict.id !== existing.id) {
        throw new BadRequestException('Payment method code already exists');
      }
      existing.code = code;
    }

    if (typeof payload.providerId !== 'undefined') existing.providerId = payload.providerId;
    if (typeof payload.name !== 'undefined') existing.name = payload.name;
    if (typeof payload.description !== 'undefined') existing.description = payload.description;
    if (typeof payload.isActive !== 'undefined') existing.isActive = payload.isActive;
    if (typeof payload.channels !== 'undefined') {
      existing.channels = this.normalizeChannelCodes(payload.channels) ?? [];
    }
    if (typeof payload.configJson !== 'undefined') existing.configJson = payload.configJson ?? {};
    if (typeof payload.metadata !== 'undefined') existing.metadata = payload.metadata ?? {};

    return this.methodRepo.save(existing);
  }

  async delete(id: string): Promise<{ deleted: boolean }> {
    const existing = await this.methodRepo.findOne({ where: { id } });
    if (!existing) throw new NotFoundException('Payment method not found');

    const res = await this.methodRepo.delete(id);
    return { deleted: (res.affected || 0) > 0 };
  }
}
