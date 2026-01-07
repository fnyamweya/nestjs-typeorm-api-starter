import { BadRequestException, Injectable } from '@nestjs/common';
import { ApiClientService } from 'src/common/api-client/api-client.service';
import { WhatsappConfigService } from './whatsapp-config.service';

interface CreateTemplateInput {
  name: string;
  language: string;
  category: string;
  components: Array<Record<string, unknown>>;
}

interface MetaCreateTemplateResponse {
  id?: string;
  status?: string;
  [key: string]: unknown;
}

interface ListTemplatesInput {
  name?: string;
  status?: string;
  category?: string;
  language?: string;
  limit?: number;
  after?: string;
  before?: string;
}

export interface MetaListTemplateItem {
  id?: string;
  name?: string;
  language?: string;
  category?: string;
  status?: string;
  components?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}

export interface MetaListTemplateResponse {
  data?: MetaListTemplateItem[];
  paging?: {
    cursors?: {
      before?: string;
      after?: string;
    };
    next?: string;
    previous?: string;
  };
  [key: string]: unknown;
}

export interface MetaGetTemplateResponse extends MetaListTemplateItem {
  [key: string]: unknown;
}

interface SendTemplateMessageInput {
  to: string;
  name: string;
  language: string;
  components?: Array<Record<string, unknown>>;
}

interface SendTextMessageInput {
  to: string;
  body: string;
}

@Injectable()
export class WhatsappApiService {
  constructor(
    private readonly configService: WhatsappConfigService,
    private readonly apiClient: ApiClientService,
  ) {}

  private ensureMetaProvider(provider: string) {
    if (provider !== 'meta') {
      throw new BadRequestException('Unsupported WhatsApp provider');
    }
  }

  async createTemplate(
    input: CreateTemplateInput,
  ): Promise<MetaCreateTemplateResponse> {
    const config = await this.configService.getConfig();
    if (!config.enabled) {
      throw new BadRequestException('WhatsApp is not enabled');
    }
    this.ensureMetaProvider(config.provider);

    if (!config.accessToken || !config.businessAccountId) {
      throw new BadRequestException(
        'WhatsApp provider credentials are missing',
      );
    }

    const path = `/${config.apiVersion}/${config.businessAccountId}/message_templates`;

    const res = await this.apiClient.request<MetaCreateTemplateResponse>({
      method: 'POST',
      baseUrl: config.baseUrl,
      path,
      headers: {
        Authorization: `Bearer ${config.accessToken}`,
        'Content-Type': 'application/json',
      },
      data: {
        name: input.name,
        language: input.language,
        category: input.category,
        components: input.components,
      },
      operation: 'whatsapp.createTemplate',
    });

    return res.data;
  }

  async listTemplates(
    input: ListTemplatesInput = {},
  ): Promise<MetaListTemplateResponse> {
    const config = await this.configService.getConfig();
    if (!config.enabled) {
      throw new BadRequestException('WhatsApp is not enabled');
    }
    this.ensureMetaProvider(config.provider);

    if (!config.accessToken || !config.businessAccountId) {
      throw new BadRequestException(
        'WhatsApp provider credentials are missing',
      );
    }

    const path = `/${config.apiVersion}/${config.businessAccountId}/message_templates`;

    const params: Record<string, string | number> = {
      fields: 'id,name,language,category,components,status',
    };

    if (input.name) params.name = input.name;
    if (input.status) params.status = input.status;
    if (input.category) params.category = input.category;
    if (input.language) params.language = input.language;
    if (typeof input.limit === 'number') params.limit = input.limit;
    if (input.after) params.after = input.after;
    if (input.before) params.before = input.before;

    const res = await this.apiClient.request<MetaListTemplateResponse>({
      method: 'GET',
      baseUrl: config.baseUrl,
      path,
      headers: {
        Authorization: `Bearer ${config.accessToken}`,
      },
      params,
      operation: 'whatsapp.listTemplates',
    });

    return res.data;
  }

  async getTemplate(templateId: string): Promise<MetaGetTemplateResponse> {
    const config = await this.configService.getConfig();
    if (!config.enabled) {
      throw new BadRequestException('WhatsApp is not enabled');
    }
    this.ensureMetaProvider(config.provider);

    if (!config.accessToken) {
      throw new BadRequestException(
        'WhatsApp provider credentials are missing',
      );
    }

    if (!templateId?.trim()) {
      throw new BadRequestException('Template id is required');
    }

    const path = `/${config.apiVersion}/${templateId}`;

    const res = await this.apiClient.request<MetaGetTemplateResponse>({
      method: 'GET',
      baseUrl: config.baseUrl,
      path,
      headers: {
        Authorization: `Bearer ${config.accessToken}`,
      },
      params: {
        fields: 'id,name,language,category,components,status',
      },
      operation: 'whatsapp.getTemplate',
    });

    return res.data;
  }

  async sendTemplateMessage(input: SendTemplateMessageInput) {
    const config = await this.configService.getConfig();
    if (!config.enabled) {
      throw new BadRequestException('WhatsApp is not enabled');
    }
    this.ensureMetaProvider(config.provider);

    if (!config.accessToken || !config.phoneNumberId) {
      throw new BadRequestException(
        'WhatsApp provider credentials are missing',
      );
    }

    const path = `/${config.apiVersion}/${config.phoneNumberId}/messages`;

    const res = await this.apiClient.request({
      method: 'POST',
      baseUrl: config.baseUrl,
      path,
      headers: {
        Authorization: `Bearer ${config.accessToken}`,
        'Content-Type': 'application/json',
      },
      data: {
        messaging_product: 'whatsapp',
        to: input.to,
        type: 'template',
        template: {
          name: input.name,
          language: { code: input.language },
          ...(input.components?.length ? { components: input.components } : {}),
        },
      },
      operation: 'whatsapp.sendTemplateMessage',
    });

    return res.data;
  }

  async sendTextMessage(input: SendTextMessageInput) {
    const config = await this.configService.getConfig();
    if (!config.enabled) {
      throw new BadRequestException('WhatsApp is not enabled');
    }
    this.ensureMetaProvider(config.provider);

    if (!config.accessToken || !config.phoneNumberId) {
      throw new BadRequestException(
        'WhatsApp provider credentials are missing',
      );
    }

    const path = `/${config.apiVersion}/${config.phoneNumberId}/messages`;

    const res = await this.apiClient.request({
      method: 'POST',
      baseUrl: config.baseUrl,
      path,
      headers: {
        Authorization: `Bearer ${config.accessToken}`,
        'Content-Type': 'application/json',
      },
      data: {
        messaging_product: 'whatsapp',
        to: input.to,
        type: 'text',
        text: { body: input.body },
      },
      operation: 'whatsapp.sendTextMessage',
    });

    return res.data;
  }
}
