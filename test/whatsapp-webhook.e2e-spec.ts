import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';
import * as crypto from 'node:crypto';
import { WhatsappWebhookController } from '../src/whatsapp/controllers/whatsapp-webhook.controller';
import { WhatsappConfigService } from '../src/whatsapp/services/whatsapp-config.service';

describe('WhatsApp Webhook (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      controllers: [WhatsappWebhookController],
      providers: [
        {
          provide: WhatsappConfigService,
          useValue: {
            getConfig: async () =>
              ({
                provider: 'meta',
                accessToken: '',
                businessAccountId: '',
                phoneNumberId: '',
                apiVersion: 'v19.0',
                baseUrl: 'https://graph.facebook.com',
                enabled: true,
                appSecret: 'e2e_test_app_secret',
                webhookVerifyToken: 'e2e_verify_token',
              }) as any,
          },
        },
      ],
    }).compile();

    app = moduleRef.createNestApplication({ rawBody: true });
    await app.init();
  }, 120000);

  afterAll(async () => {
    if (app) await app.close();
  });

  it('accepts a correctly signed request (proves rawBody is available)', async () => {
    const rawBody = JSON.stringify({ hello: 'world' });
    const digest = crypto
      .createHmac('sha256', 'e2e_test_app_secret')
      .update(rawBody)
      .digest('hex');

    await request(app.getHttpServer())
      .post('/whatsapp/webhook')
      .set('Content-Type', 'application/json')
      .set('X-Hub-Signature-256', `sha256=${digest}`)
      .send(rawBody)
      .expect(200)
      .expect('EVENT_RECEIVED');
  });

  it('rejects an incorrectly signed request', async () => {
    const rawBody = JSON.stringify({ hello: 'world' });

    await request(app.getHttpServer())
      .post('/whatsapp/webhook')
      .set('Content-Type', 'application/json')
      .set('X-Hub-Signature-256', 'sha256=deadbeef')
      .send(rawBody)
      .expect(403);
  });
});
