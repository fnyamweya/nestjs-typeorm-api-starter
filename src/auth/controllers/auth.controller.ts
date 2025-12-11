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
import { CustomerLoginDto } from '../dto/customer-login.dto';
import { AdminLoginDto } from '../dto/admin-login.dto';
import { CustomerRegisterDto } from '../dto/customer-register.dto';
import { AdminRegisterDto } from '../dto/admin-register.dto';
import { OAuthAdminProfile } from '../interfaces/oauth-admin-profile.interface';
import {
  ApiBadRequestResponse,
    ApiCreatedResponse,
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiOperation,
  ApiExcludeEndpoint,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { RequireRoles } from '../decorators/roles.decorator';
import { RolesGuard } from '../guards/roles.guard';
import { CreateAdminInviteDto } from '../dto/create-admin-invite.dto';
import { AcceptAdminInviteDto } from '../dto/accept-admin-invite.dto';
import { DeclineAdminInviteDto } from '../dto/decline-admin-invite.dto';

@Controller('auth')
@ApiTags('Authentication')
export class AuthController {
  constructor(
    private authService: AuthService,
    private twoFactorService: TwoFactorService,
    private s3ClientUtils: S3ClientUtils,
  ) {}

  @Post('login')
  @HttpCode(200)
  @ApiOperation({ summary: 'Authenticate a user and obtain access tokens' })
  @ApiOkResponse({ description: 'Login successful' })
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
  @ApiOkResponse({ description: 'Customer login successful' })
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
  @ApiOperation({ summary: 'Admin login with MFA' })
  @ApiOkResponse({ description: 'Admin login successful' })
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

  @UseGuards(JwtAuthGuard, RolesGuard)
  @RequireRoles('Super Admin')
  @Post('admin/invite')
  @HttpCode(201)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Invite a new admin user (Super Admin only)' })
  @ApiCreatedResponse({ description: 'Invitation created and email sent' })
  @ApiForbiddenResponse({ description: 'Insufficient role' })
  async inviteAdmin(
    @CurrentUser() user: AuthenticatedUser,
    @Body() createAdminInviteDto: CreateAdminInviteDto,
  ) {
    const result = await this.authService.createAdminInvite(
      createAdminInviteDto,
      user,
    );
    return ResponseUtil.created(result, 'Admin invitation sent');
  }

  @Post('admin/invite/accept')
  @HttpCode(200)
  @ApiOperation({ summary: 'Accept an admin invitation and set password' })
  @ApiOkResponse({ description: 'Invitation accepted and account activated' })
  @ApiBadRequestResponse({ description: 'Invalid or expired invitation' })
  async acceptAdminInvite(
    @Body() acceptAdminInviteDto: AcceptAdminInviteDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.acceptAdminInvite(
      acceptAdminInviteDto,
      request,
    );
    return ResponseUtil.success(result, 'Admin invitation accepted');
  }

  @Post('admin/invite/decline')
  @HttpCode(200)
  @ApiOperation({ summary: 'Decline an admin invitation' })
  @ApiOkResponse({ description: 'Invitation declined' })
  @ApiBadRequestResponse({ description: 'Invalid or expired invitation' })
  async declineAdminInvite(@Body() declineAdminInviteDto: DeclineAdminInviteDto) {
    const result = await this.authService.declineAdminInvite(
      declineAdminInviteDto,
    );
    return ResponseUtil.success(result, 'Admin invitation declined');
  }

  @Get('admin/google')
  @UseGuards(AuthGuard('admin-google'))
  @ApiOperation({ summary: 'Initiate Google OAuth 2.0 login for admins' })
  @ApiOkResponse({ description: 'Redirecting to Google OAuth 2.0' })
  async googleAdminAuth() {
    return ResponseUtil.success(
      null,
      'Redirecting to Google OAuth 2.0 for authentication',
    );
  }

  @Get('admin/google/callback')
  @UseGuards(AuthGuard('admin-google'))
  @ApiOperation({ summary: 'Google OAuth 2.0 callback for admin login' })
  @ApiOkResponse({ description: 'Admin login via Google successful' })
  async googleAdminCallback(@Req() request: Request) {
    const profile = request.user as OAuthAdminProfile;
    const result = await this.authService.loginAdminWithOAuth(
      profile,
      request,
    );
    return ResponseUtil.success(result, 'Admin login via Google successful');
  }

  @Get('admin/apple')
  @UseGuards(AuthGuard('admin-apple'))
  @ApiOperation({ summary: 'Initiate Sign in with Apple for admins' })
  @ApiOkResponse({ description: 'Redirecting to Apple login' })
  async appleAdminAuth() {
    return ResponseUtil.success(
      null,
      'Redirecting to Apple for authentication',
    );
  }

  @Post('admin/apple/callback')
  @UseGuards(AuthGuard('admin-apple'))
  @HttpCode(200)
  @ApiOperation({ summary: 'Apple callback handler for admin login' })
  @ApiOkResponse({ description: 'Admin login via Apple successful' })
  async appleAdminCallback(@Req() request: Request) {
    const profile = request.user as OAuthAdminProfile;
    const result = await this.authService.loginAdminWithOAuth(
      profile,
      request,
    );
    return ResponseUtil.success(result, 'Admin login via Apple successful');
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
    files: Express.Multer.File[],
    @Body() updateProfileDto: UpdateProfileDto,
    @Req() request: Request,
  ) {
    const profileImage = files.find(
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

  @ApiExcludeEndpoint()
  @Post('verify-2fa')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Verify a two-factor authentication code and sign in the user',
  })
  @ApiOkResponse({ description: 'Two-factor authentication successful' })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired verification code',
  })
  async verifyTwoFactor(
    @Body() verifyTwoFactorDto: VerifyTwoFactorDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.verifyTwoFactorAndLogin(
      verifyTwoFactorDto.userId,
      verifyTwoFactorDto.code,
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
    const result = await this.twoFactorService.verifyTwoFactor(
      verifyTwoFactorDto.userId,
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
    summary: 'Send a password reset verification code to the user email',
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
      'Forgot password reset OTP code sent to your email',
    );
  }

  @Post('otp/verify/forgot-password')
  @HttpCode(200)
  @ApiOperation({ summary: 'Verify the password reset OTP code' })
  @ApiOkResponse({ description: 'Password reset code verified successfully' })
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
