import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiExtraModels,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  getSchemaPath,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { WhatsappTemplateService } from '../services/whatsapp-template.service';
import { CreateWhatsappTemplateDto } from '../dto/create-whatsapp-template.dto';
import { UpdateWhatsappTemplateDto } from '../dto/update-whatsapp-template.dto';
import { FilterWhatsappTemplateDto } from '../dto/filter-whatsapp-template.dto';
import { FetchWhatsappProviderTemplatesDto } from '../dto/fetch-whatsapp-provider-templates.dto';
import {
  MetaTemplateButtonDto,
  MetaTemplateComponentDto,
} from '../dto/meta-whatsapp-template-component.dto';

@Controller('whatsapp/templates')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@ApiTags('WhatsApp: Templates')
@ApiBearerAuth('access-token')
@ApiExtraModels(
  CreateWhatsappTemplateDto,
  MetaTemplateComponentDto,
  MetaTemplateButtonDto,
)
export class WhatsappTemplatesController {
  constructor(private readonly templateService: WhatsappTemplateService) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'create',
  })
  @ApiOperation({ summary: 'Create WhatsApp template' })
  @ApiBody({
    schema: { $ref: getSchemaPath(CreateWhatsappTemplateDto) },
    examples: {
      bodyOnly: {
        summary: 'Meta template (BODY only)',
        value: {
          name: 'order_confirmation_v2',
          language: 'en_US',
          category: 'UTILITY',
          components: [
            {
              type: 'BODY',
              text: 'Hi {{1}}, your order {{2}} was placed successfully.',
            },
          ],
          submitToProvider: true,
        },
      },
      headerAndButtons: {
        summary: 'Meta template (HEADER + BODY + BUTTONS)',
        value: {
          name: 'order_tracking',
          language: 'en_US',
          category: 'UTILITY',
          components: [
            {
              type: 'HEADER',
              format: 'TEXT',
              text: 'Order update',
            },
            {
              type: 'BODY',
              text: 'Hi {{1}}, track your order {{2}} here: {{3}}',
            },
            {
              type: 'BUTTONS',
              buttons: [
                {
                  type: 'URL',
                  text: 'Track order',
                  url: 'https://example.com/orders/{{1}}',
                },
              ],
            },
          ],
          submitToProvider: true,
        },
      },
    },
  })
  @ApiCreatedResponse({ description: 'Template created successfully' })
  async create(@Body() payload: CreateWhatsappTemplateDto) {
    const template = await this.templateService.create(payload);
    return ResponseUtil.created(template, 'Template created successfully');
  }

  @Get()
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({ summary: 'List WhatsApp templates' })
  @ApiOkResponse({ description: 'Templates retrieved successfully' })
  async findAll(@Query() filters: FilterWhatsappTemplateDto) {
    const templates = await this.templateService.findAll(filters);
    return ResponseUtil.success(templates, 'Templates retrieved successfully');
  }

  @Get('/provider')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({ summary: 'Fetch WhatsApp templates from provider' })
  @ApiOkResponse({ description: 'Provider templates retrieved successfully' })
  async fetchProvider(@Query() filters: FetchWhatsappProviderTemplatesDto) {
    const templates =
      await this.templateService.fetchProviderTemplates(filters);
    return ResponseUtil.success(
      templates,
      'Provider templates retrieved successfully',
    );
  }

  @Get('/provider/:id')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({ summary: 'Fetch a WhatsApp template from provider by id' })
  @ApiOkResponse({ description: 'Provider template retrieved successfully' })
  async fetchProviderOne(@Param('id') id: string) {
    const template = await this.templateService.fetchProviderTemplate(id);
    return ResponseUtil.success(
      template,
      'Provider template retrieved successfully',
    );
  }

  @Get('/:id')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({ summary: 'Get WhatsApp template' })
  @ApiOkResponse({ description: 'Template retrieved successfully' })
  async findOne(@Param('id') id: string) {
    const template = await this.templateService.findOne(id);
    return ResponseUtil.success(template, 'Template retrieved successfully');
  }

  @Patch('/:id')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Update WhatsApp template' })
  @ApiOkResponse({ description: 'Template updated successfully' })
  async update(
    @Param('id') id: string,
    @Body() payload: UpdateWhatsappTemplateDto,
  ) {
    const template = await this.templateService.update(id, payload);
    return ResponseUtil.updated(template, 'Template updated successfully');
  }

  @Post('/:id/submit')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Submit template to WhatsApp provider' })
  @ApiOkResponse({ description: 'Template submitted successfully' })
  async submit(@Param('id') id: string) {
    const template = await this.templateService.submit(id);
    return ResponseUtil.success(template, 'Template submitted successfully');
  }

  @Delete('/:id')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'delete',
  })
  @ApiOperation({ summary: 'Delete WhatsApp template' })
  @ApiOkResponse({ description: 'Template deleted successfully' })
  async remove(@Param('id') id: string) {
    await this.templateService.remove(id);
    return ResponseUtil.deleted('Template deleted successfully');
  }
}
