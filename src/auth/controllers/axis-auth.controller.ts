import { Controller, Get, Req, UseGuards, VERSION_NEUTRAL } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { ResponseUtil } from 'src/common/utils/response.util';
import { AdminGoogleOAuthGuard } from '../guards/admin-google-oauth.guard';
import { OAuthAdminProfile } from '../interfaces/oauth-admin-profile.interface';
import { AuthService } from '../services/auth.service';

@Controller({ path: 'axis/auth', version: VERSION_NEUTRAL })
@ApiTags('Authentication')
export class AxisAuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('google')
  @UseGuards(AdminGoogleOAuthGuard)
  @ApiOperation({ summary: 'Initiate Google OAuth 2.0 login for admins (Axis UI)' })
  @ApiOkResponse({ description: 'Redirecting to Google OAuth 2.0' })
  async googleAdminAuth() {
    return ResponseUtil.success(
      null,
      'Redirecting to Google OAuth 2.0 for authentication',
    );
  }

  @Get('google/callback')
  @UseGuards(AdminGoogleOAuthGuard)
  @ApiOperation({ summary: 'Google OAuth 2.0 callback for admin login (Axis UI)' })
  @ApiOkResponse({ description: 'Admin login via Google successful' })
  async googleAdminCallback(@Req() request: Request) {
    const profile = request.user as OAuthAdminProfile;
    const result = await this.authService.loginAdminWithOAuth(profile, request);
    return ResponseUtil.success(result, 'Admin login via Google successful');
  }
}
