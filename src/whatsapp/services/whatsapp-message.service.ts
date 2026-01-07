import { BadRequestException, Injectable } from '@nestjs/common';
import { SendWhatsappMessageDto } from '../dto/send-whatsapp-message.dto';
import { WhatsappApiService } from './whatsapp-api.service';
import { WhatsappTemplateService } from './whatsapp-template.service';

@Injectable()
export class WhatsappMessageService {
  constructor(
    private readonly apiService: WhatsappApiService,
    private readonly templateService: WhatsappTemplateService,
  ) {}

  async send(payload: SendWhatsappMessageDto) {
    const type = payload.type ?? 'template';

    if (type === 'text') {
      if (!payload.text) {
        throw new BadRequestException('text is required for text messages');
      }

      const response = await this.apiService.sendTextMessage({
        to: payload.to,
        body: payload.text,
      });

      return { type: 'text', response };
    }

    const template = payload.templateId
      ? await this.templateService.findOne(payload.templateId)
      : null;

    const templateName = payload.templateName ?? template?.name;
    if (!templateName) {
      throw new BadRequestException('templateName or templateId is required');
    }

    const language = payload.language ?? template?.language ?? 'en_US';
    const components =
      payload.components ??
      (template?.defaultComponentsJson?.length
        ? template.defaultComponentsJson
        : undefined);

    const response = await this.apiService.sendTemplateMessage({
      to: payload.to,
      name: templateName,
      language,
      components,
    });

    return {
      type: 'template',
      templateId: template?.id,
      templateName,
      language,
      response,
    };
  }
}
