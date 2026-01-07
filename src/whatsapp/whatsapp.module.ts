import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Setting } from 'src/setting/entities/setting.entity';
import { WhatsappTemplate } from './entities/whatsapp-template.entity';
import { WhatsappConfigService } from './services/whatsapp-config.service';
import { WhatsappApiService } from './services/whatsapp-api.service';
import { WhatsappTemplateService } from './services/whatsapp-template.service';
import { WhatsappMessageService } from './services/whatsapp-message.service';
import { WhatsappTemplatesController } from './controllers/whatsapp-templates.controller';
import { WhatsappMessagesController } from './controllers/whatsapp-messages.controller';
import { WhatsappWebhookController } from './controllers/whatsapp-webhook.controller';
import { WhatsappTemplateSeeder } from './seeders/whatsapp-template.seeder';

@Module({
  imports: [TypeOrmModule.forFeature([Setting, WhatsappTemplate])],
  controllers: [
    WhatsappTemplatesController,
    WhatsappMessagesController,
    WhatsappWebhookController,
  ],
  providers: [
    WhatsappConfigService,
    WhatsappApiService,
    WhatsappTemplateService,
    WhatsappMessageService,
    WhatsappTemplateSeeder,
  ],
  exports: [WhatsappTemplateService, WhatsappMessageService],
})
export class WhatsappModule {}
