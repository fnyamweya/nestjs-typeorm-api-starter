import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UseGuards,
  VERSION_NEUTRAL,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { ResponseUtil } from 'src/common/utils/response.util';
import { GoogleOAuthGuard } from '../guards/google-oauth.guard';
import { OAuthProfile } from '../interfaces/oauth-profile.interface';
import { AuthService } from '../services/auth.service';
import { OAuthExchangeService } from '../services/oauth-exchange.service';
import { OAuthExchangeDto } from '../dto/oauth-exchange.dto';

@Controller({ path: 'auth', version: VERSION_NEUTRAL })
@ApiTags('Authentication')
export class PublicAuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly oauthExchangeService: OAuthExchangeService,
  ) {}

  private normalizeRedirectPath(raw: unknown): string | null {
    if (typeof raw !== 'string') return null;
    const value = raw.trim();
    if (!value) return null;
    // Only allow same-origin relative redirects to avoid open redirect vulnerabilities.
    if (!value.startsWith('/')) return null;
    if (value.startsWith('//')) return null;
    return value;
  }

  private appendQueryParam(urlLike: string, key: string, value: string): string {
    const [beforeHash, hash] = urlLike.split('#', 2);
    const sep = beforeHash.includes('?') ? '&' : '?';
    const updated = `${beforeHash}${sep}${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
    return hash ? `${updated}#${hash}` : updated;
  }

  @Get(':oauthKey/google/callback')
  @UseGuards(GoogleOAuthGuard)
  @ApiOperation({
    summary:
      'Google OAuth 2.0 callback using a profile key (no /api prefix)',
  })
  @ApiOkResponse({ description: 'Login via Google successful' })
  async googleCallbackByKey(
    @Req() request: Request,
    @Res({ passthrough: false }) response: Response,
  ) {
    const profile = request.user as OAuthProfile;

    const { userId } = await this.authService.authorizeWithGoogleOAuth(
      profile,
      request,
    );

    const exchangeCode = await this.oauthExchangeService.issue(userId);

    const redirectRaw = (request as any).__oauthRedirect as string | undefined;
    const redirectPath = this.normalizeRedirectPath(redirectRaw);

    if (!redirectPath) {
      return response.status(200).json(
        ResponseUtil.success(
          { exchangeCode },
          'OAuth successful. Exchange code issued.',
        ),
      );
    }

    const location = this.appendQueryParam(
      redirectPath,
      'exchangeCode',
      exchangeCode,
    );
    return response.redirect(302, location);
  }

  @Get(':oauthKey/google')
  @UseGuards(GoogleOAuthGuard)
  @ApiOperation({
    summary:
      'Initiate Google OAuth 2.0 login using a profile key (no /api prefix)',
  })
  @ApiOkResponse({ description: 'Redirecting to Google OAuth 2.0' })
  async googleAuthByKey() {
    return ResponseUtil.success(
      null,
      'Redirecting to Google OAuth 2.0 for authentication',
    );
  }

  @Post('oauth/exchange')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Exchange a one-time OAuth exchangeCode for login tokens (any role)',
    description:
      'Used after the server-side OAuth callback redirects back to the client with an exchangeCode.',
  })
  @ApiOkResponse({ description: 'Login successful' })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({ description: 'Invalid or expired exchangeCode' })
  async oauthExchange(@Body() dto: OAuthExchangeDto, @Req() request: Request) {
    const { userId } = await this.oauthExchangeService.consume(dto.exchangeCode);
    const result = await this.authService.loginUserById(userId, request);
    return ResponseUtil.success(result, 'Login successful');
  }
}
