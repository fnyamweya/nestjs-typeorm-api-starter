import {
  Body,
  Controller,
  Post,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { WhatsappMessageService } from '../services/whatsapp-message.service';
import { SendWhatsappMessageDto } from '../dto/send-whatsapp-message.dto';

@Controller('whatsapp/messages')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@UseGuards(JwtAuthGuard, PermissionsGuard)
@ApiTags('WhatsApp: Messages')
@ApiBearerAuth('access-token')
export class WhatsappMessagesController {
  constructor(private readonly messageService: WhatsappMessageService) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'create',
  })
  @ApiOperation({ summary: 'Send WhatsApp message' })
  @ApiCreatedResponse({ description: 'Message sent successfully' })
  async send(@Body() payload: SendWhatsappMessageDto) {
    const result = await this.messageService.send(payload);
    return ResponseUtil.created(result, 'Message sent successfully');
  }
}
