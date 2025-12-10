import {
  Controller,
  UseGuards,
  Post,
  Get,
  Body,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { LogActivity } from 'src/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/activity-log/entities/user-activity-log.entity';
import { SettingService } from '../services/setting.service';
import { CreateSMTPDto } from '../dto/create-smtp-setting.dto';
import { SMTPResponseDto } from '../dto/smtp-response.dto';
import { ResponseUtil } from 'src/common/utils/response.util';
import { ApiResponse } from 'src/common/interfaces/api-response.interface';
import { CreateSMSSettingDto } from '../dto/create-sms-setting.dto';
import { SMSResponseDto } from '../dto/sms-response.dto';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
  ApiBadRequestResponse,
} from '@nestjs/swagger';

@Controller('settings')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@ApiTags('Settings')
@ApiBearerAuth('access-token')
export class SettingController {
  constructor(private readonly settingService: SettingService) {}

  @Post('smtp')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'create',
  })
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'SMTP settings setup successfully',
    resourceType: 'smtp-settings',
  })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create or update SMTP configuration' })
  @ApiBody({ type: CreateSMTPDto })
  @ApiCreatedResponse({
    description: 'SMTP settings setup successfully',
    type: SMTPResponseDto,
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to manage settings',
  })
  async createSMTPSettings(
    @Body() createSMTPDto: CreateSMTPDto,
  ): Promise<ApiResponse<SMTPResponseDto>> {
    const smtpSettings =
      await this.settingService.createSMTPSettings(createSMTPDto);
    return ResponseUtil.created(
      smtpSettings,
      'SMTP settings setup successfully',
    );
  }

  @Get('smtp')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve configured SMTP settings' })
  @ApiOkResponse({
    description: 'SMTP settings retrieved successfully',
    type: SMTPResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to view settings',
  })
  async getSMTPSettings(): Promise<ApiResponse<SMTPResponseDto>> {
    const smtpSettings = await this.settingService.getSMTPSettings();
    return ResponseUtil.success(
      smtpSettings,
      'SMTP settings retrieved successfully',
    );
  }

  @Post('sms')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'create',
  })
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'SMS settings setup successfully',
    resourceType: 'sms-settings',
  })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create or update SMS configuration' })
  @ApiBody({ type: CreateSMSSettingDto })
  @ApiCreatedResponse({
    description: 'SMS settings setup successfully',
    type: SMSResponseDto,
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to manage settings',
  })
  async createSMSSettings(
    @Body() createSMSSettingDto: CreateSMSSettingDto,
  ): Promise<ApiResponse<SMSResponseDto>> {
    const smsSettings = await this.settingService.createSMSSettings(
      createSMSSettingDto,
    );
    return ResponseUtil.created(
      smsSettings,
      'SMS settings setup successfully',
    );
  }

  @Get('sms')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve configured SMS settings' })
  @ApiOkResponse({
    description: 'SMS settings retrieved successfully',
    type: SMSResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to view settings',
  })
  async getSMSSettings(): Promise<ApiResponse<SMSResponseDto>> {
    const smsSettings = await this.settingService.getSMSSettings();
    return ResponseUtil.success(
      smsSettings,
      'SMS settings retrieved successfully',
    );
  }
}
