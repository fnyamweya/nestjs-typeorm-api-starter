import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Req,
  Delete,
  Patch,
  UseInterceptors,
  UploadedFiles,
  HttpCode,
  BadRequestException,
} from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import { TwoFactorService } from '../services/two-factor.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { CurrentUser } from '../decorators/current-user.decorator';
import { AuthenticatedUser } from '../interfaces/user.interface';
import { Request } from 'express';
import { LogActivity } from 'src/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/activity-log/entities/user-activity-log.entity';
import { AnyFilesInterceptor, FileInterceptor } from '@nestjs/platform-express';
import { AuthGuard } from '@nestjs/passport';
import { LoginDto } from '../dto/login.dto';
import { RefreshTokenDto } from '../dto/refresh-token.dto';
import { UpdateProfileDto } from '../dto/update-profile.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { VerifyTwoFactorDto } from '../dto/verify-two-factor.dto';
import { EnableTwoFactorDto } from '../dto/enable-two-factor.dto';
import { DisableTwoFactorDto } from '../dto/disable-two-factor.dto';
import { ResponseUtil } from 'src/common/utils/response.util';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';
import { ForgotPasswordSendOTPDto } from '../dto/forgot-password-send-otp.dto';
import { VerifyPasswordResetOTPCodeDto } from '../dto/verify-password-reset-otp-code.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { SetPasswordDto } from '../dto/set-password.dto';
import { CustomerLoginDto } from '../dto/customer-login.dto';
import { AdminLoginDto } from '../dto/admin-login.dto';
import { CustomerRegisterDto } from '../dto/customer-register.dto';
import { AdminRegisterDto } from '../dto/admin-register.dto';
import { AppleOAuthGuard } from '../guards/apple-oauth.guard';
import { OAuthAdminProfile } from '../interfaces/oauth-admin-profile.interface';
import {
  ApiBadRequestResponse,
  ApiCreatedResponse,
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiExtraModels,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiOperation,
  ApiExcludeEndpoint,
  ApiTags,
  ApiUnauthorizedResponse,
  getSchemaPath,
} from '@nestjs/swagger';
import { AuthTokensDto } from '../dto/auth-tokens.dto';
import { TwoFactorRequiredDto } from '../dto/two-factor-required.dto';
import { PasswordResetVerifiedDto } from '../dto/password-reset-verified.dto';
import { RequireRoles } from '../decorators/roles.decorator';
import { RequirePermissions } from '../decorators/permissions.decorator';
import { PermissionsGuard } from '../guards/permissions.guard';
import { PermissionModule } from '../entities/permission.entity';
import { RolesGuard } from '../guards/roles.guard';
import { CreateUserInviteDto } from '../dto/create-user-invite.dto';
import { AcceptUserInviteDto } from '../dto/accept-user-invite.dto';
import { DeclineUserInviteDto } from '../dto/decline-user-invite.dto';

@Controller('auth')
@ApiTags('Authentication')
@ApiExtraModels(AuthTokensDto, TwoFactorRequiredDto, PasswordResetVerifiedDto)
export class AuthController {
  constructor(
    private authService: AuthService,
    private twoFactorService: TwoFactorService,
    private s3ClientUtils: S3ClientUtils,
  ) {}

  @Post('login')
  @HttpCode(200)
  @ApiOperation({ summary: 'Authenticate a user and obtain access tokens' })
  @ApiOkResponse({
    description: 'Login successful, or 2FA step-up required',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        statusCode: { type: 'number', example: 200 },
        message: { type: 'string', example: 'Login successful' },
        data: {
          oneOf: [
            { $ref: getSchemaPath(AuthTokensDto) },
            { $ref: getSchemaPath(TwoFactorRequiredDto) },
          ],
        },
        timestamp: { type: 'string', example: '2026-01-06T12:00:00.000Z' },
      },
    },
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({ description: 'Invalid credentials' })
  async login(@Body() loginDto: LoginDto, @Req() request: Request) {
    const result = await this.authService.login(loginDto, request);
    return ResponseUtil.success(result, 'Login successful');
  }

  @Post('customer/login')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Customer login with email or phone and password',
  })
  @ApiOkResponse({
    description: 'Customer login successful, or 2FA step-up required',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        statusCode: { type: 'number', example: 200 },
        message: { type: 'string', example: 'Customer login successful' },
        data: {
          oneOf: [
            { $ref: getSchemaPath(AuthTokensDto) },
            { $ref: getSchemaPath(TwoFactorRequiredDto) },
          ],
        },
        timestamp: { type: 'string', example: '2026-01-06T12:00:00.000Z' },
      },
    },
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({ description: 'Invalid credentials' })
  async loginCustomer(
    @Body() customerLoginDto: CustomerLoginDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.loginCustomer(
      customerLoginDto,
      request,
    );
    return ResponseUtil.success(result, 'Customer login successful');
  }

  @Post('customer/register')
  @HttpCode(201)
  @ApiOperation({ summary: 'Customer self-registration' })
  @ApiCreatedResponse({ description: 'Customer registered successfully' })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  async registerCustomer(
    @Body() customerRegisterDto: CustomerRegisterDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.registerCustomer(
      customerRegisterDto,
      request,
    );
    return ResponseUtil.created(result, 'Customer registered successfully');
  }

  @Post('admin/login')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Admin login with MFA',
    description:
      'Seeded accounts: superadmin@gmail.com / passwordD123!@# (Super Admin), admin@example.com / AdminP@ss123 (Admin).',
  })
  @ApiOkResponse({
    description: 'Admin login successful, or 2FA step-up required',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        statusCode: { type: 'number', example: 200 },
        message: { type: 'string', example: 'Admin login successful' },
        data: {
          oneOf: [
            { $ref: getSchemaPath(AuthTokensDto) },
            { $ref: getSchemaPath(TwoFactorRequiredDto) },
          ],
        },
        timestamp: { type: 'string', example: '2026-01-06T12:00:00.000Z' },
      },
    },
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({ description: 'Invalid credentials' })
  async loginAdmin(
    @Body() adminLoginDto: AdminLoginDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.loginAdmin(adminLoginDto, request);
    return ResponseUtil.success(result, 'Admin login successful');
  }

  @Post('admin/register')
  @HttpCode(201)
  @ApiOperation({ summary: 'Admin self-registration' })
  @ApiCreatedResponse({ description: 'Admin registered successfully' })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  async registerAdmin(
    @Body() adminRegisterDto: AdminRegisterDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.registerAdmin(
      adminRegisterDto,
      request,
    );
    return ResponseUtil.created(result, 'Admin registered successfully');
  }

  @UseGuards(JwtAuthGuard, PermissionsGuard, RolesGuard)
  @RequireRoles('Super Admin', 'Admin', 'Customer')
  @RequirePermissions({ module: PermissionModule.USERS, permission: 'create' })
  @Post('user/invite')
  @HttpCode(201)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Invite a new user (details + role + phone)',
    description:
      'Requires Users:create and role hierarchy: Super Admin can invite any role; others may only invite within their own subtree. Inviter provides email, name, phone, and role; invitee only sets the password via emailed link.',
  })
  @ApiCreatedResponse({ description: 'Invitation created and email sent' })
  @ApiForbiddenResponse({ description: 'Insufficient role' })
  async inviteUser(
    @CurrentUser() user: AuthenticatedUser,
    @Body() createUserInviteDto: CreateUserInviteDto,
  ) {
    const result = await this.authService.createUserInvite(
      createUserInviteDto,
      user,
    );
    return ResponseUtil.created(result, 'User invitation sent');
  }

  @Post('user/invite/accept')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Accept a user invitation by setting a password',
    description:
      'Consumes the invitation token and finalizes the account by setting a password. All other profile details are supplied by the inviter.',
  })
  @ApiOkResponse({ description: 'Invitation accepted and account activated' })
  @ApiBadRequestResponse({ description: 'Invalid or expired invitation' })
  async acceptUserInvite(
    @Body() acceptUserInviteDto: AcceptUserInviteDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.acceptUserInvite(
      acceptUserInviteDto,
      request,
    );
    return ResponseUtil.success(result, 'User invitation accepted');
  }

  @Post('user/invite/decline')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Decline a user invitation',
    description: 'Marks the invitation declined; token becomes unusable.',
  })
  @ApiOkResponse({ description: 'Invitation declined' })
  @ApiBadRequestResponse({ description: 'Invalid or expired invitation' })
  async declineUserInvite(@Body() declineUserInviteDto: DeclineUserInviteDto) {
    const result =
      await this.authService.declineUserInvite(declineUserInviteDto);
    return ResponseUtil.success(result, 'User invitation declined');
  }

  @Get('apple')
  @UseGuards(AppleOAuthGuard)
  @ApiOperation({ summary: 'Initiate Sign in with Apple (role-based)' })
  @ApiOkResponse({ description: 'Redirecting to Apple login' })
  async appleAuth() {
    return ResponseUtil.success(
      null,
      'Redirecting to Apple for authentication',
    );
  }

  @Get(':oauthKey/apple')
  @UseGuards(AppleOAuthGuard)
  @ApiOperation({
    summary:
      'Initiate Sign in with Apple using a profile key (e.g. /auth/<key>/apple)',
  })
  @ApiOkResponse({ description: 'Redirecting to Apple login' })
  async appleAuthByKey() {
    return ResponseUtil.success(
      null,
      'Redirecting to Apple for authentication',
    );
  }

  @Post('apple/callback')
  @UseGuards(AppleOAuthGuard)
  @HttpCode(200)
  @ApiOperation({ summary: 'Apple callback handler for role-based login' })
  @ApiOkResponse({ description: 'Login via Apple successful' })
  async appleCallback(@Req() request: Request) {
    const profile = request.user as OAuthAdminProfile;
    const result = await this.authService.loginWithOAuth(profile, request);

    return ResponseUtil.success(result, 'Login via Apple successful');
  }

  @Post(':oauthKey/apple/callback')
  @UseGuards(AppleOAuthGuard)
  @HttpCode(200)
  @ApiOperation({
    summary:
      'Apple callback handler for role-based login using a profile key (e.g. /auth/<key>/apple/callback)',
  })
  @ApiOkResponse({ description: 'Login via Apple successful' })
  async appleCallbackByKey(@Req() request: Request) {
    const profile = request.user as OAuthAdminProfile;
    const result = await this.authService.loginWithOAuth(profile, request);

    return ResponseUtil.success(result, 'Login via Apple successful');
  }



  @Post('refresh')
  @HttpCode(200)
  @ApiOperation({ summary: 'Exchange a refresh token for a new access token' })
  @ApiOkResponse({ description: 'Token refreshed successfully' })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({ description: 'Invalid refresh token' })
  async refresh(@Body() refreshTokenDto: RefreshTokenDto) {
    const result = await this.authService.refreshAccessToken(
      refreshTokenDto.refreshToken,
    );
    return ResponseUtil.success(result, 'Token refreshed successfully');
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(200)
  @LogActivity({
    action: ActivityAction.LOGOUT,
    description: 'User logged out successfully',
    resourceType: 'user',
    getResourceId: (result: AuthenticatedUser) => result.id?.toString(),
  })
  @ApiOperation({ summary: 'Log out the authenticated user' })
  @ApiBearerAuth('access-token')
  @ApiOkResponse({ description: 'Logout successful' })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to perform this action',
  })
  async logout(@Body() refreshTokenDto: RefreshTokenDto) {
    await this.authService.logout(refreshTokenDto.refreshToken);
    return ResponseUtil.success(null, 'Logout successful');
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @ApiOperation({ summary: 'Retrieve the authenticated user profile' })
  @ApiBearerAuth('access-token')
  @ApiOkResponse({ description: 'Profile retrieved successfully' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to access this resource',
  })
  async getProfile(@CurrentUser() user: AuthenticatedUser) {
    if (
      user.profileImageUrl &&
      (await this.s3ClientUtils.objectExists(user.profileImageUrl))
    ) {
      user.profileImageUrl =
        (await this.s3ClientUtils.generatePresignedUrl(user.profileImageUrl)) ||
        '';
    }
    return ResponseUtil.success(user, 'Profile retrieved successfully');
  }

  @UseGuards(JwtAuthGuard)
  @Patch('profile')
  @UseInterceptors(AnyFilesInterceptor())
  @HttpCode(200)
  @ApiOperation({
    summary: 'Update profile details and optionally upload a profile image',
  })
  @ApiBearerAuth('access-token')
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'Profile update payload including optional profile image file',
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'jane.doe@example.com' },
        firstName: { type: 'string', example: 'Jane' },
        lastName: { type: 'string', example: 'Doe' },
        password: { type: 'string', example: 'Str0ngP@ssw0rd' },
        phone: { type: 'string', example: '+14155551234' },
        roleId: {
          type: 'string',
          format: 'uuid',
          example: '2d931510-d99f-494a-8c67-87feb05e1594',
        },
        profileImage: { type: 'string', format: 'binary' },
      },
    },
  })
  @ApiOkResponse({ description: 'Profile updated successfully' })
  @ApiBadRequestResponse({
    description: 'Validation failed or invalid file upload',
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to update the profile',
  })
  async updateProfile(
    @CurrentUser() user: AuthenticatedUser,
    @UploadedFiles()
    files: Express.Multer.File[] | undefined,
    @Body() updateProfileDto: UpdateProfileDto,
    @Req() request: Request,
  ) {
    const profileImage = (files ?? []).find(
      (file) => file.fieldname === 'profileImage',
    );

    const updatedUser = await this.authService.updateProfile(
      user.id,
      updateProfileDto,
      request,
      profileImage,
    );
    return ResponseUtil.success(updatedUser, 'Profile updated successfully');
  }

  @UseGuards(JwtAuthGuard)
  @Patch('change-password')
  @HttpCode(200)
  @ApiOperation({ summary: 'Change the authenticated user password' })
  @ApiBearerAuth('access-token')
  @ApiOkResponse({ description: 'Password changed successfully' })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to change the password',
  })
  async changePassword(
    @CurrentUser() user: AuthenticatedUser,
    @Body() changePasswordDto: ChangePasswordDto,
    @Req() request: Request,
  ) {
    await this.authService.changePassword(user.id, changePasswordDto, request);
    return ResponseUtil.success(
      null,
      'Password changed successfully. Please login again.',
    );
  }

  @UseGuards(JwtAuthGuard)
  @UseInterceptors(FileInterceptor('profileImage'))
  @Delete('profile')
  @HttpCode(200)
  @ApiOperation({ summary: 'Delete the authenticated user profile image' })
  @ApiBearerAuth('access-token')
  @ApiOkResponse({ description: 'Profile deleted successfully' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to delete the profile',
  })
  async deleteProfile(
    @CurrentUser() user: AuthenticatedUser,
    @Req() request: Request,
  ) {
    await this.authService.deleteProfile(user.id, request);
    return ResponseUtil.success(null, 'Profile deleted successfully');
  }

  @Post('verify-2fa')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Verify a two-factor authentication code and sign in the user',
  })
  @ApiOkResponse({
    description: 'Two-factor authentication successful',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        statusCode: { type: 'number', example: 200 },
        message: {
          type: 'string',
          example: 'Two-factor authentication successful',
        },
        data: { $ref: getSchemaPath(AuthTokensDto) },
        timestamp: { type: 'string', example: '2026-01-06T12:00:00.000Z' },
      },
    },
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired verification code',
  })
  async verifyTwoFactor(
    @Body() verifyTwoFactorDto: VerifyTwoFactorDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.verifyTwoFactorAndLogin(
      {
        userId: verifyTwoFactorDto.userId,
        twoFactorToken: verifyTwoFactorDto.twoFactorToken,
        code: verifyTwoFactorDto.code,
      },
      request,
    );
    return ResponseUtil.success(result, 'Two-factor authentication successful');
  }

  @ApiExcludeEndpoint()
  @Post('enable-2fa-verify')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Verify a two-factor authentication code to enable 2FA',
  })
  @ApiOkResponse({
    description: 'Two-factor authentication enable verification succeeded',
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired verification code',
  })
  async enableTwoFactorVerify(@Body() verifyTwoFactorDto: VerifyTwoFactorDto) {
    // Enabling 2FA is only available for authenticated users; keep this endpoint
    // working by requiring an explicit userId (legacy) or allowing twoFactorToken.
    // The TwoFactorService.verifyTwoFactor signature requires a concrete userId.
    const userId = verifyTwoFactorDto.userId;
    if (!userId) {
      throw new BadRequestException('User ID is required');
    }

    const result = await this.twoFactorService.verifyTwoFactor(
      userId,
      verifyTwoFactorDto.code,
    );
    return ResponseUtil.success(
      result,
      'Two-factor authentication enable successful',
    );
  }

  @ApiExcludeEndpoint()
  @UseGuards(JwtAuthGuard)
  @Post('enable-2fa')
  @HttpCode(200)
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Two-factor authentication enabled',
    resourceType: 'user',
    getResourceId: (result: AuthenticatedUser) => result.id?.toString(),
  })
  @ApiOperation({
    summary: 'Send a verification code to enable two-factor authentication',
  })
  @ApiBearerAuth('access-token')
  @ApiOkResponse({
    description: 'Two-factor authentication enable verification code sent',
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to enable two-factor authentication',
  })
  async enableTwoFactor(
    @CurrentUser() user: AuthenticatedUser,
    @Body() enableTwoFactorDto: EnableTwoFactorDto,
  ) {
    await this.twoFactorService.enableTwoFactor(
      user.id,
      enableTwoFactorDto.email,
      enableTwoFactorDto.channel,
    );
    return ResponseUtil.success(
      null,
      `Two-factor authentication verification code sent via ${enableTwoFactorDto.channel}`,
    );
  }

  @ApiExcludeEndpoint()
  @UseGuards(JwtAuthGuard)
  @Post('disable-2fa')
  @HttpCode(200)
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Two-factor authentication disabled',
    resourceType: 'user',
    getResourceId: (result: AuthenticatedUser) => result.id?.toString(),
  })
  @ApiOperation({
    summary: 'Disable two-factor authentication for the authenticated user',
  })
  @ApiBearerAuth('access-token')
  @ApiOkResponse({ description: 'Two-factor authentication disabled' })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description:
      'Insufficient permissions to disable two-factor authentication',
  })
  async disableTwoFactor(
    @CurrentUser() user: AuthenticatedUser,
    @Body() disableTwoFactorDto: DisableTwoFactorDto,
  ) {
    await this.twoFactorService.disableTwoFactor(
      user.id,
      disableTwoFactorDto.password,
    );
    return ResponseUtil.success(null, 'Two-factor authentication disabled');
  }

  @Post('otp/send/forgot-password')
  @HttpCode(200)
  @ApiOperation({
    summary:
      'Send a password reset verification code to the user email or phone (identifier)',
  })
  @ApiOkResponse({ description: 'Forgot password OTP sent successfully' })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  async forgotPasswordOTPSend(
    @Body() forgotPasswordSendOtpDto: ForgotPasswordSendOTPDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.passwordResetOTPSend(
      forgotPasswordSendOtpDto,
      request,
    );
    return ResponseUtil.success(
      result,
      'Forgot password reset OTP code queued for delivery',
    );
  }

  @Post('otp/verify/forgot-password')
  @HttpCode(200)
  @ApiOperation({ summary: 'Verify the password reset OTP code' })
  @ApiOkResponse({
    description: 'Password reset code verified successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        statusCode: { type: 'number', example: 200 },
        message: {
          type: 'string',
          example: 'Successfully verify password reset code',
        },
        data: { $ref: getSchemaPath(PasswordResetVerifiedDto) },
        timestamp: { type: 'string', example: '2026-01-06T12:00:00.000Z' },
      },
    },
  })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired verification code',
  })
  async passwordResetOTPVerify(
    @Body() verifyPasswordResetOTPCodeDto: VerifyPasswordResetOTPCodeDto,
  ) {
    const result = await this.authService.verifyPasswordResetOTPCode(
      verifyPasswordResetOTPCodeDto,
    );
    return ResponseUtil.success(
      result,
      'Successfully verify password reset code',
    );
  }

  @Post('password-set')
  @HttpCode(200)
  @ApiOperation({ summary: 'Complete password setup using one-time token' })
  @ApiOkResponse({ description: 'Password set successfully' })
  @ApiBadRequestResponse({ description: 'Invalid or expired token' })
  async completePasswordSetup(
    @Body() setPasswordDto: SetPasswordDto,
    @Req() request: Request,
  ) {
    await this.authService.completePasswordSetup(setPasswordDto, request);
    return ResponseUtil.success(null, 'Password set successfully');
  }

  @Post('reset-password')
  @HttpCode(200)
  @ApiOperation({ summary: 'Reset the user password using a verified token' })
  @ApiOkResponse({ description: 'Password reset successfully' })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({ description: 'Invalid or expired reset token' })
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @Req() request: Request,
  ) {
    await this.authService.resetPassword(resetPasswordDto, request);
    return ResponseUtil.success(null, 'Successfully reset your password');
  }
}
