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
import { CreateWhatsappSettingDto } from '../dto/create-whatsapp-setting.dto';
import { WhatsappResponseDto } from '../dto/whatsapp-response.dto';
import { UpdateWhatsappSecretsDto } from '../dto/update-whatsapp-secrets.dto';
import { WhatsappSecretsResponseDto } from '../dto/whatsapp-secrets-response.dto';
import { CreateS3SettingDto } from '../dto/create-s3-setting.dto';
import { S3ResponseDto } from '../dto/s3-response.dto';
import { UpdateS3SecretsDto } from '../dto/update-s3-secrets.dto';
import { S3SecretsResponseDto } from '../dto/s3-secrets-response.dto';
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
    const smsSettings =
      await this.settingService.createSMSSettings(createSMSSettingDto);
    return ResponseUtil.created(smsSettings, 'SMS settings setup successfully');
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

  @Post('whatsapp')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'create',
  })
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'WhatsApp settings setup successfully',
    resourceType: 'whatsapp-settings',
  })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create or update WhatsApp configuration' })
  @ApiBody({ type: CreateWhatsappSettingDto })
  @ApiCreatedResponse({
    description: 'WhatsApp settings setup successfully',
    type: WhatsappResponseDto,
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to manage settings',
  })
  async createWhatsappSettings(
    @Body() createWhatsappSettingDto: CreateWhatsappSettingDto,
  ): Promise<ApiResponse<WhatsappResponseDto>> {
    const whatsappSettings = await this.settingService.createWhatsappSettings(
      createWhatsappSettingDto,
    );
    return ResponseUtil.created(
      whatsappSettings,
      'WhatsApp settings setup successfully',
    );
  }

  @Get('whatsapp')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve configured WhatsApp settings' })
  @ApiOkResponse({
    description: 'WhatsApp settings retrieved successfully',
    type: WhatsappResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to view settings',
  })
  async getWhatsappSettings(): Promise<ApiResponse<WhatsappResponseDto>> {
    const whatsappSettings = await this.settingService.getWhatsappSettings();
    return ResponseUtil.success(
      whatsappSettings,
      'WhatsApp settings retrieved successfully',
    );
  }

  @Post('whatsapp/secrets')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'WhatsApp webhook secrets updated successfully',
    resourceType: 'whatsapp-secrets',
  })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Update WhatsApp webhook secrets (app secret + verify token)',
    description:
      'Stores secrets encrypted at rest. Values are never returned in responses; only presence booleans.',
  })
  @ApiBody({ type: UpdateWhatsappSecretsDto })
  @ApiOkResponse({
    description: 'WhatsApp webhook secrets updated successfully',
    type: WhatsappSecretsResponseDto,
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to manage settings',
  })
  async updateWhatsappSecrets(
    @Body() payload: UpdateWhatsappSecretsDto,
  ): Promise<ApiResponse<WhatsappSecretsResponseDto>> {
    const data = await this.settingService.updateWhatsappSecrets(payload);
    return ResponseUtil.success(
      data,
      'WhatsApp webhook secrets updated successfully',
    );
  }

  @Post('s3')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'create',
  })
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'S3 settings setup successfully',
    resourceType: 's3-settings',
  })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create or update S3 (object storage) configuration',
  })
  @ApiBody({ type: CreateS3SettingDto })
  @ApiCreatedResponse({
    description: 'S3 settings setup successfully',
    type: S3ResponseDto,
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to manage settings',
  })
  async createS3Settings(
    @Body() dto: CreateS3SettingDto,
  ): Promise<ApiResponse<S3ResponseDto>> {
    const data = await this.settingService.createS3Settings(dto);
    return ResponseUtil.created(data, 'S3 settings setup successfully');
  }

  @Get('s3')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve configured S3 (object storage) settings' })
  @ApiOkResponse({
    description: 'S3 settings retrieved successfully',
    type: S3ResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to view settings',
  })
  async getS3Settings(): Promise<ApiResponse<S3ResponseDto>> {
    const data = await this.settingService.getS3Settings();
    return ResponseUtil.success(data, 'S3 settings retrieved successfully');
  }

  @Post('s3/secrets')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'S3 credentials updated successfully',
    resourceType: 's3-secrets',
  })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Update S3 credentials (access key + secret key)',
    description:
      'Stores secrets encrypted at rest. Values are never returned in responses; only presence booleans.',
  })
  @ApiBody({ type: UpdateS3SecretsDto })
  @ApiOkResponse({
    description: 'S3 credentials updated successfully',
    type: S3SecretsResponseDto,
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to manage settings',
  })
  async updateS3Secrets(
    @Body() payload: UpdateS3SecretsDto,
  ): Promise<ApiResponse<S3SecretsResponseDto>> {
    const data = await this.settingService.updateS3Secrets(payload);
    return ResponseUtil.success(data, 'S3 credentials updated successfully');
  }
}
