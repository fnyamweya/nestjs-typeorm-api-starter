import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CustomerTier } from './entities/customer-tier.entity';
import { CustomerTierRule } from './entities/customer-tier-rule.entity';
import { CreateCustomerTierDto } from './dto/create-customer-tier.dto';
import { UpdateCustomerTierDto } from './dto/update-customer-tier.dto';
import { CreateCustomerTierRuleDto } from './dto/create-customer-tier-rule.dto';
import { UpdateCustomerTierRuleDto } from './dto/update-customer-tier-rule.dto';
import { CustomerTierDto } from './dto/customer-tier.dto';
import { CustomerTierRuleDto } from './dto/customer-tier-rule.dto';
import { CustomerProfile } from 'src/user/entities/customer-profile.entity';
import { User } from 'src/user/entities/user.entity';
import { Order, FinancialStatus } from 'src/order/entities/order.entity';
import { resolveCustomerTier } from './utils/customer-tier.util';

@Injectable()
export class CustomerTierService {
  constructor(
    @InjectRepository(CustomerTier)
    private readonly tierRepository: Repository<CustomerTier>,
    @InjectRepository(CustomerTierRule)
    private readonly ruleRepository: Repository<CustomerTierRule>,
    @InjectRepository(CustomerProfile)
    private readonly customerProfileRepository: Repository<CustomerProfile>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Order)
    private readonly orderRepository: Repository<Order>,
  ) {}

  private normalizeCode(code: string): string {
    const normalized = (code ?? '').trim().toUpperCase();
    if (!normalized) throw new BadRequestException('Tier code cannot be empty');
    return normalized;
  }

  private toTierDto(row: CustomerTier): CustomerTierDto {
    return {
      id: row.id,
      code: row.code,
      name: row.name,
      priority: row.priority,
      isActive: row.isActive,
      configJson: (row.configJson ?? {}) as any,
      metadata: (row.metadata ?? {}) as any,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
    };
  }

  private toRuleDto(row: CustomerTierRule): CustomerTierRuleDto {
    return {
      id: row.id,
      tierId: row.tierId,
      tierCode: row.tier?.code ?? '',
      isActive: row.isActive,
      priority: row.priority,
      validFrom: row.validFrom ? row.validFrom.toISOString() : undefined,
      validUntil: row.validUntil ? row.validUntil.toISOString() : undefined,
      rule: (row.ruleJson ?? {}) as any,
      description: row.description,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
    };
  }

  async listTiers(): Promise<CustomerTierDto[]> {
    const rows = await this.tierRepository.find({
      order: { priority: 'DESC', code: 'ASC' },
    });
    return rows.map((r) => this.toTierDto(r));
  }

  async createTier(payload: CreateCustomerTierDto): Promise<CustomerTierDto> {
    const code = this.normalizeCode(payload.code);

    const exists = await this.tierRepository.exist({ where: { code } as any });
    if (exists) throw new BadRequestException('Tier code already exists');

    const row = this.tierRepository.create({
      code,
      name: payload.name.trim(),
      priority: payload.priority ?? 0,
      isActive: payload.isActive ?? true,
      configJson: payload.configJson ?? {},
      metadata: payload.metadata ?? {},
    });

    const saved = await this.tierRepository.save(row);
    return this.toTierDto(saved);
  }

  async updateTier(
    code: string,
    payload: UpdateCustomerTierDto,
  ): Promise<CustomerTierDto> {
    const normalized = this.normalizeCode(code);
    const row = await this.tierRepository.findOne({
      where: { code: normalized } as any,
    });
    if (!row) throw new NotFoundException('Tier not found');

    if (payload.code && this.normalizeCode(payload.code) !== normalized) {
      throw new BadRequestException('Tier code cannot be changed');
    }

    Object.assign(row, {
      name: payload.name !== undefined ? payload.name.trim() : row.name,
      priority: payload.priority ?? row.priority,
      isActive: payload.isActive ?? row.isActive,
      configJson: payload.configJson ?? row.configJson,
      metadata: payload.metadata ?? row.metadata,
    });

    const saved = await this.tierRepository.save(row);
    return this.toTierDto(saved);
  }

  async deleteTier(code: string): Promise<void> {
    const normalized = this.normalizeCode(code);
    const row = await this.tierRepository.findOne({
      where: { code: normalized } as any,
    });
    if (!row) throw new NotFoundException('Tier not found');
    await this.tierRepository.remove(row);
  }

  async listRules(): Promise<CustomerTierRuleDto[]> {
    const rows = await this.ruleRepository.find({
      relations: ['tier'],
      order: { priority: 'DESC', createdAt: 'ASC' },
    });
    return rows.map((r) => this.toRuleDto(r));
  }

  async createRule(
    payload: CreateCustomerTierRuleDto,
  ): Promise<CustomerTierRuleDto> {
    const tier = await this.tierRepository.findOne({
      where: { id: payload.tierId } as any,
    });
    if (!tier) throw new NotFoundException('Tier not found');

    const row = this.ruleRepository.create({
      tierId: payload.tierId,
      isActive: payload.isActive ?? true,
      priority: payload.priority ?? 0,
      validFrom: payload.validFrom ? new Date(payload.validFrom) : undefined,
      validUntil: payload.validUntil ? new Date(payload.validUntil) : undefined,
      ruleJson: (payload.rule ?? {}) as any,
      description: payload.description,
    });

    const saved = await this.ruleRepository.save(row);
    const withTier = await this.ruleRepository.findOne({
      where: { id: saved.id } as any,
      relations: ['tier'],
    });
    return this.toRuleDto(withTier!);
  }

  async updateRule(
    id: string,
    payload: UpdateCustomerTierRuleDto,
  ): Promise<CustomerTierRuleDto> {
    const row = await this.ruleRepository.findOne({
      where: { id } as any,
      relations: ['tier'],
    });
    if (!row) throw new NotFoundException('Rule not found');

    if (payload.tierId && payload.tierId !== row.tierId) {
      const tier = await this.tierRepository.findOne({
        where: { id: payload.tierId } as any,
      });
      if (!tier) throw new NotFoundException('Tier not found');
      row.tierId = payload.tierId;
    }

    Object.assign(row, {
      isActive: payload.isActive ?? row.isActive,
      priority: payload.priority ?? row.priority,
      validFrom:
        payload.validFrom !== undefined
          ? payload.validFrom
            ? new Date(payload.validFrom)
            : undefined
          : row.validFrom,
      validUntil:
        payload.validUntil !== undefined
          ? payload.validUntil
            ? new Date(payload.validUntil)
            : undefined
          : row.validUntil,
      ruleJson: payload.rule ?? row.ruleJson,
      description: payload.description ?? row.description,
    });

    const saved = await this.ruleRepository.save(row);
    const withTier = await this.ruleRepository.findOne({
      where: { id: saved.id } as any,
      relations: ['tier'],
    });
    return this.toRuleDto(withTier!);
  }

  async deleteRule(id: string): Promise<void> {
    const row = await this.ruleRepository.findOne({ where: { id } as any });
    if (!row) throw new NotFoundException('Rule not found');
    await this.ruleRepository.remove(row);
  }

  async setCustomerTierOverride(
    userId: string,
    tierCode?: string,
  ): Promise<void> {
    const profile = await this.customerProfileRepository.findOne({
      where: { userId } as any,
    });
    if (!profile) throw new NotFoundException('Customer profile not found');

    const normalized = tierCode ? this.normalizeCode(tierCode) : '';
    if (normalized) {
      const tier = await this.tierRepository.findOne({
        where: { code: normalized, isActive: true } as any,
      });
      if (!tier) throw new BadRequestException('Unknown or inactive tier');
      profile.tierOverrideCode = normalized;
      profile.tierId = tier.id;
    } else {
      profile.tierOverrideCode = null;
      profile.tierId = null;
    }

    await this.customerProfileRepository.save(profile);
  }

  async resolveTierForUser(
    userId: string,
  ): Promise<{ tierCode: string; source: string; matchedRuleId?: string }> {
    const user = await this.userRepository.findOne({
      where: { id: userId } as any,
      relations: ['customerProfile'],
    });
    if (!user) throw new NotFoundException('User not found');

    const profile = user.customerProfile;

    // Manual override (if active)
    const overrideTierId = profile?.tierId ?? null;
    if (overrideTierId) {
      const tier = await this.tierRepository.findOne({
        where: { id: overrideTierId, isActive: true } as any,
      });
      if (tier) {
        // Keep the legacy code field in sync for backwards compatibility/visibility
        if (profile && profile.tierOverrideCode !== tier.code) {
          try {
            profile.tierOverrideCode = tier.code;
            await this.customerProfileRepository.save(profile);
          } catch {
            // ignore
          }
        }
        return { tierCode: tier.code, source: 'manual' };
      }
    }

    // Legacy override fallback (no tier_id yet)
    const overrideCode = profile?.tierOverrideCode ?? null;
    if (overrideCode) {
      const tier = await this.tierRepository.findOne({
        where: { code: overrideCode, isActive: true } as any,
      });
      if (tier) {
        // Best-effort backfill tier_id for future lookups
        if (profile && !profile.tierId) {
          try {
            profile.tierId = tier.id;
            await this.customerProfileRepository.save(profile);
          } catch {
            // ignore
          }
        }
        return { tierCode: tier.code, source: 'manual' };
      }
    }

    const stats = await this.orderRepository
      .createQueryBuilder('o')
      .select('COUNT(*)', 'ordersCount')
      .addSelect('COALESCE(SUM(o.grand_total::numeric), 0)', 'lifetimeSpend')
      .addSelect(
        'MAX(COALESCE(o.completed_at, o.placed_at, o.created_at))',
        'lastOrderAt',
      )
      .where('o.customer_id = :userId', { userId })
      .andWhere('o.financial_status = :paid', { paid: FinancialStatus.PAID })
      .getRawOne<{
        ordersCount: string;
        lifetimeSpend: string;
        lastOrderAt: string | null;
      }>();

    const facts = {
      userId: user.id,
      email: user.email,
      phone: user.phone,
      customerSince: user.createdAt?.toISOString(),
      loyaltyStatus: profile?.loyaltyStatus,
      loyaltyPoints: profile?.loyaltyPoints,
      ordersCount: Number(stats?.ordersCount ?? 0),
      lifetimeSpend: Number(stats?.lifetimeSpend ?? 0),
      lastOrderAt: stats?.lastOrderAt ?? null,
      emailDomain: user.email?.includes('@')
        ? user.email.split('@')[1]
        : undefined,
    };

    const rules = await this.ruleRepository.find({
      relations: ['tier'],
      order: { priority: 'DESC', createdAt: 'ASC' },
    });

    const activeRules = rules
      .filter((r) => r.tier?.isActive)
      .map((r) => ({
        id: r.id,
        tierCode: r.tier.code,
        priority: r.priority,
        isActive: r.isActive,
        validFrom: r.validFrom,
        validUntil: r.validUntil,
        ruleJson: (r.ruleJson ?? {}) as any,
      }));

    const resolved = resolveCustomerTier({
      rules: activeRules,
      facts,
      defaultTierCode: 'BASE',
    });

    // Persist resolved tier for observability (best-effort, avoid throwing)
    if (profile) {
      try {
        profile.tierResolvedCode = resolved.tierCode;
        profile.tierResolvedAt = new Date();
        await this.customerProfileRepository.save(profile);
      } catch {
        // ignore
      }
    }

    return {
      tierCode: resolved.tierCode,
      source: resolved.source,
      matchedRuleId: resolved.matchedRuleId,
    };
  }
}
