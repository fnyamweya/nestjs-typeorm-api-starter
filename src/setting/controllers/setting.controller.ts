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
import { CreateGoogleOAuthSettingDto } from '../dto/create-google-oauth-setting.dto';
import { UpdateGoogleOAuthSecretDto } from '../dto/update-google-oauth-secret.dto';
import { GoogleOAuthResponseDto } from '../dto/google-oauth-response.dto';
import { CreateGoogleOAuthCustomerSettingDto } from '../dto/create-google-oauth-customer-setting.dto';
import { UpdateGoogleOAuthCustomerSecretDto } from '../dto/update-google-oauth-customer-secret.dto';
import { GoogleOAuthCustomerResponseDto } from '../dto/google-oauth-customer-response.dto';
import { CreateAppleOAuthSettingDto } from '../dto/create-apple-oauth-setting.dto';
import { UpdateAppleOAuthSecretDto } from '../dto/update-apple-oauth-secret.dto';
import { AppleOAuthResponseDto } from '../dto/apple-oauth-response.dto';
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

  @Post('oauth/google')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Google OAuth settings updated successfully',
    resourceType: 'oauth-google-settings',
  })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create or update Google OAuth settings' })
  @ApiBody({ type: CreateGoogleOAuthSettingDto })
  @ApiCreatedResponse({
    description: 'Google OAuth settings updated successfully',
    type: GoogleOAuthResponseDto,
  })
  async createGoogleOAuthSettings(
    @Body() dto: CreateGoogleOAuthSettingDto,
  ): Promise<ApiResponse<GoogleOAuthResponseDto>> {
    const data = await this.settingService.createGoogleOAuthSettings(dto);
    return ResponseUtil.created(data, 'Google OAuth settings updated successfully');
  }

  @Post('oauth/google/secret')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Google OAuth client secret updated successfully',
    resourceType: 'oauth-google-secret',
  })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Update Google OAuth client secret',
    description:
      'Stores the secret encrypted at rest. Secret values are never returned in responses.',
  })
  @ApiBody({ type: UpdateGoogleOAuthSecretDto })
  @ApiOkResponse({
    description: 'Google OAuth client secret updated successfully',
    type: GoogleOAuthResponseDto,
  })
  async updateGoogleOAuthSecret(
    @Body() dto: UpdateGoogleOAuthSecretDto,
  ): Promise<ApiResponse<GoogleOAuthResponseDto>> {
    const data = await this.settingService.updateGoogleOAuthSecret(dto);
    return ResponseUtil.success(
      data,
      'Google OAuth client secret updated successfully',
    );
  }

  @Get('oauth/google')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve configured Google OAuth settings' })
  @ApiOkResponse({
    description: 'Google OAuth settings retrieved successfully',
    type: GoogleOAuthResponseDto,
  })
  async getGoogleOAuthSettings(): Promise<ApiResponse<GoogleOAuthResponseDto>> {
    const data = await this.settingService.getGoogleOAuthSettings();
    return ResponseUtil.success(
      data,
      'Google OAuth settings retrieved successfully',
    );
  }

  @Post('oauth/google/customer')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Customer Google OAuth settings updated successfully',
    resourceType: 'oauth-google-customer-settings',
  })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create or update Customer Google OAuth settings' })
  @ApiBody({ type: CreateGoogleOAuthCustomerSettingDto })
  @ApiCreatedResponse({
    description: 'Customer Google OAuth settings updated successfully',
    type: GoogleOAuthCustomerResponseDto,
  })
  async createGoogleOAuthCustomerSettings(
    @Body() dto: CreateGoogleOAuthCustomerSettingDto,
  ): Promise<ApiResponse<GoogleOAuthCustomerResponseDto>> {
    const data = await this.settingService.createGoogleOAuthCustomerSettings(
      dto,
    );
    return ResponseUtil.created(
      data,
      'Customer Google OAuth settings updated successfully',
    );
  }

  @Post('oauth/google/customer/secret')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Customer Google OAuth client secret updated successfully',
    resourceType: 'oauth-google-customer-secret',
  })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Update Customer Google OAuth client secret',
    description:
      'Stores the secret encrypted at rest. Secret values are never returned in responses.',
  })
  @ApiBody({ type: UpdateGoogleOAuthCustomerSecretDto })
  @ApiOkResponse({
    description: 'Customer Google OAuth client secret updated successfully',
    type: GoogleOAuthCustomerResponseDto,
  })
  async updateGoogleOAuthCustomerSecret(
    @Body() dto: UpdateGoogleOAuthCustomerSecretDto,
  ): Promise<ApiResponse<GoogleOAuthCustomerResponseDto>> {
    const data = await this.settingService.updateGoogleOAuthCustomerSecret(dto);
    return ResponseUtil.success(
      data,
      'Customer Google OAuth client secret updated successfully',
    );
  }

  @Get('oauth/google/customer')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve configured Customer Google OAuth settings' })
  @ApiOkResponse({
    description: 'Customer Google OAuth settings retrieved successfully',
    type: GoogleOAuthCustomerResponseDto,
  })
  async getGoogleOAuthCustomerSettings(): Promise<
    ApiResponse<GoogleOAuthCustomerResponseDto>
  > {
    const data = await this.settingService.getGoogleOAuthCustomerSettings();
    return ResponseUtil.success(
      data,
      'Customer Google OAuth settings retrieved successfully',
    );
  }

  @Post('oauth/apple')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Apple OAuth settings updated successfully',
    resourceType: 'oauth-apple-settings',
  })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create or update Apple OAuth settings' })
  @ApiBody({ type: CreateAppleOAuthSettingDto })
  @ApiCreatedResponse({
    description: 'Apple OAuth settings updated successfully',
    type: AppleOAuthResponseDto,
  })
  async createAppleOAuthSettings(
    @Body() dto: CreateAppleOAuthSettingDto,
  ): Promise<ApiResponse<AppleOAuthResponseDto>> {
    const data = await this.settingService.createAppleOAuthSettings(dto);
    return ResponseUtil.created(data, 'Apple OAuth settings updated successfully');
  }

  @Post('oauth/apple/secret')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Apple OAuth private key updated successfully',
    resourceType: 'oauth-apple-secret',
  })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Update Apple OAuth private key',
    description:
      'Stores the private key encrypted at rest. Secret values are never returned in responses.',
  })
  @ApiBody({ type: UpdateAppleOAuthSecretDto })
  @ApiOkResponse({
    description: 'Apple OAuth private key updated successfully',
    type: AppleOAuthResponseDto,
  })
  async updateAppleOAuthSecret(
    @Body() dto: UpdateAppleOAuthSecretDto,
  ): Promise<ApiResponse<AppleOAuthResponseDto>> {
    const data = await this.settingService.updateAppleOAuthSecret(dto);
    return ResponseUtil.success(
      data,
      'Apple OAuth private key updated successfully',
    );
  }

  @Get('oauth/apple')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve configured Apple OAuth settings' })
  @ApiOkResponse({
    description: 'Apple OAuth settings retrieved successfully',
    type: AppleOAuthResponseDto,
  })
  async getAppleOAuthSettings(): Promise<ApiResponse<AppleOAuthResponseDto>> {
    const data = await this.settingService.getAppleOAuthSettings();
    return ResponseUtil.success(
      data,
      'Apple OAuth settings retrieved successfully',
    );
  }

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
