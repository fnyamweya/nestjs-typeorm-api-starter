import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { WhatsappTemplate } from '../entities/whatsapp-template.entity';
import { CreateWhatsappTemplateDto } from '../dto/create-whatsapp-template.dto';
import { UpdateWhatsappTemplateDto } from '../dto/update-whatsapp-template.dto';
import { FilterWhatsappTemplateDto } from '../dto/filter-whatsapp-template.dto';
import { WhatsappApiService } from './whatsapp-api.service';
import { FetchWhatsappProviderTemplatesDto } from '../dto/fetch-whatsapp-provider-templates.dto';

@Injectable()
export class WhatsappTemplateService {
  constructor(
    @InjectRepository(WhatsappTemplate)
    private readonly templateRepository: Repository<WhatsappTemplate>,
    private readonly apiService: WhatsappApiService,
  ) {}

  async create(payload: CreateWhatsappTemplateDto) {
    const exists = await this.templateRepository.exist({
      where: { name: payload.name },
    });
    if (exists) {
      throw new BadRequestException('Template name already exists');
    }

    const template = this.templateRepository.create({
      name: payload.name,
      language: payload.language ?? 'en_US',
      category: payload.category,
      status: 'draft',
      isActive: payload.isActive ?? true,
      componentsJson: payload.components as unknown as Array<
        Record<string, unknown>
      >,
      defaultComponentsJson: payload.defaultComponents ?? [],
      metaJson: payload.metaJson ?? {},
    });

    const saved = await this.templateRepository.save(template);

    if (payload.submitToProvider) {
      await this.submit(saved.id);
    }

    return this.findOne(saved.id);
  }

  async findAll(filters: FilterWhatsappTemplateDto) {
    const qb = this.templateRepository.createQueryBuilder('t');

    if (filters.name) {
      qb.andWhere('t.name ILIKE :name', { name: `%${filters.name}%` });
    }
    if (filters.category) {
      qb.andWhere('t.category = :category', { category: filters.category });
    }
    if (filters.status) {
      qb.andWhere('t.status = :status', { status: filters.status });
    }
    if (filters.isActive !== undefined) {
      qb.andWhere('t.isActive = :isActive', { isActive: filters.isActive });
    }

    return qb.orderBy('t.createdAt', 'DESC').getMany();
  }

  async fetchProviderTemplates(filters: FetchWhatsappProviderTemplatesDto) {
    const { name, category, status, language, limit, after, before } = filters;
    return this.apiService.listTemplates({
      name,
      category,
      status,
      language,
      limit,
      after,
      before,
    });
  }

  async fetchProviderTemplate(id: string) {
    return this.apiService.getTemplate(id);
  }

  async findOne(id: string) {
    const template = await this.templateRepository.findOne({ where: { id } });
    if (!template) throw new NotFoundException('WhatsApp template not found');
    return template;
  }

  async update(id: string, payload: UpdateWhatsappTemplateDto) {
    const template = await this.findOne(id);

    if (payload.name && payload.name !== template.name) {
      const exists = await this.templateRepository.exist({
        where: { name: payload.name },
      });
      if (exists) {
        throw new BadRequestException('Template name already exists');
      }
    }

    Object.assign(template, {
      name: payload.name ?? template.name,
      language: payload.language ?? template.language,
      category: payload.category ?? template.category,
      isActive: payload.isActive ?? template.isActive,
      componentsJson:
        (payload.components as unknown as
          | Array<Record<string, unknown>>
          | undefined) ?? template.componentsJson,
      defaultComponentsJson:
        payload.defaultComponents ?? template.defaultComponentsJson,
      metaJson: payload.metaJson ?? template.metaJson,
    });

    await this.templateRepository.save(template);
    if (payload.submitToProvider) {
      await this.submit(template.id);
    }
    return this.findOne(template.id);
  }

  async submit(id: string) {
    const template = await this.findOne(id);
    if (!template.isActive) {
      throw new BadRequestException('Template is disabled');
    }

    const response = await this.apiService.createTemplate({
      name: template.name,
      language: template.language,
      category: template.category,
      components: template.componentsJson,
    });

    template.providerTemplateId = response?.id ?? template.providerTemplateId;
    template.status = response?.status ?? template.status;
    template.metaJson = {
      ...template.metaJson,
      providerResponse: response ?? null,
    };

    await this.templateRepository.save(template);
    return template;
  }

  async remove(id: string) {
    const template = await this.findOne(id);
    await this.templateRepository.remove(template);
  }
}
