import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Headers,
  HttpCode,
  Logger,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import * as crypto from 'node:crypto';
import { WhatsappConfigService } from '../services/whatsapp-config.service';
import { verifyMetaWebhookSignature } from '../utils/meta-webhook-signature';

@Controller('whatsapp/webhook')
@ApiTags('WhatsApp: Webhook')
export class WhatsappWebhookController {
  private readonly logger = new Logger(WhatsappWebhookController.name);

  constructor(private readonly configService: WhatsappConfigService) {}

  private timingSafeEqualString(a: string, b: string): boolean {
    const aBuf = Buffer.from(a, 'utf8');
    const bBuf = Buffer.from(b, 'utf8');
    if (aBuf.length !== bBuf.length) return false;
    return crypto.timingSafeEqual(aBuf, bBuf);
  }

  /**
   * Meta webhook verification handshake.
   * Meta will call your callback URL with query params:
   * - hub.mode=subscribe
   * - hub.verify_token=<token you set in Meta>
   * - hub.challenge=<random string>
   */
  @Get()
  @ApiOperation({ summary: 'Verify WhatsApp webhook (Meta)' })
  async verify(
    @Query('hub.mode') mode?: string,
    @Query('hub.verify_token') verifyToken?: string,
    @Query('hub.challenge') challenge?: string,
  ) {
    const config = await this.configService.getConfig();
    const expected = config.webhookVerifyToken;

    if (!expected) {
      throw new ForbiddenException('Webhook verify token is not configured');
    }

    if (
      mode === 'subscribe' &&
      this.timingSafeEqualString(verifyToken ?? '', expected)
    ) {
      // Must return the challenge string verbatim.
      return challenge ?? '';
    }

    throw new ForbiddenException('Webhook verification failed');
  }

  /**
   * Webhook receiver.
   * Meta expects a 200 response quickly.
   */
  @Post()
  @HttpCode(200)
  @ApiOperation({ summary: 'Receive WhatsApp webhook events (Meta)' })
  async receive(
    @Req() req: Request & { rawBody?: Buffer },
    @Body() _body: unknown,
    @Headers() headers: Record<string, string | string[]>,
  ) {
    const config = await this.configService.getConfig();
    const appSecret = config.appSecret;
    if (!appSecret) {
      throw new ForbiddenException('Webhook app secret is not configured');
    }

    const rawBody = req.rawBody;
    if (!rawBody || !Buffer.isBuffer(rawBody)) {
      throw new ForbiddenException(
        'Webhook raw body is not available for signature verification',
      );
    }

    const signatureHeaderRaw =
      headers['x-hub-signature-256'] ?? headers['X-Hub-Signature-256'];
    const signatureHeader = Array.isArray(signatureHeaderRaw)
      ? signatureHeaderRaw[0]
      : signatureHeaderRaw;

    if (!signatureHeader || typeof signatureHeader !== 'string') {
      throw new ForbiddenException('Missing X-Hub-Signature-256 header');
    }

    const ok = verifyMetaWebhookSignature({
      appSecret,
      rawBody,
      signatureHeader,
    });

    if (!ok) {
      throw new ForbiddenException('Webhook signature verification failed');
    }

    this.logger.log('Webhook received (signature verified)');

    // Keep processing minimal and return 200 quickly.
    return 'EVENT_RECEIVED';
  }
}
