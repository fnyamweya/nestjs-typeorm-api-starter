import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { createTestApp, truncateDb } from './e2e/bootstrap';
import { SettingSeeder } from '../src/setting/seeders/setting.seeder';
import { LocationSeeder } from '../src/location/seeders/location.seeder';
import { CatalogSeeder } from '../src/catalog/seeders/catalog.seeder';
import { ShippingSeeder } from '../src/shipping/seeders/shipping.seeder';
import { AuthSeeder } from '../src/auth/seeders/auth.seeder';
import { ChannelsSeeder } from '../src/channels/seeders/channels.seeder';
import { ProductSku } from '../src/catalog/entities/product-sku.entity';
import { Location, LocationType } from '../src/location/entities/location.entity';
import { CheckoutSession } from '../src/checkout/entities/checkout-session.entity';

describe('Checkout E2E', () => {
  let app: INestApplication;
  let skuRepo: Repository<ProductSku>;
  let locationRepo: Repository<Location>;
  let sessionRepo: Repository<CheckoutSession>;

  beforeAll(async () => {
    const t = await createTestApp();
    app = t.app;

    await truncateDb(t.ds);

    const settingSeeder = app.get(SettingSeeder);
    const locationSeeder = app.get(LocationSeeder);
    const channelsSeeder = app.get(ChannelsSeeder);
    const authSeeder = app.get(AuthSeeder);
    const catalogSeeder = app.get(CatalogSeeder);
    const shippingSeeder = app.get(ShippingSeeder);

    await settingSeeder.seed();
    await locationSeeder.seed();
    await channelsSeeder.seed();
    await authSeeder.seed();
    await catalogSeeder.seed();
    await shippingSeeder.seed();

    skuRepo = app.get(getRepositoryToken(ProductSku));
    locationRepo = app.get(getRepositoryToken(Location));
    sessionRepo = app.get(getRepositoryToken(CheckoutSession));
  }, 120000);

  afterAll(async () => {
    if (app) await app.close();
  });

  it('runs the full checkout flow (session -> delivery -> shipping -> review -> confirm)', async () => {
    const sku = await skuRepo.findOne({ where: { sku: 'PHONE-001' } });
    expect(sku).toBeDefined();
    if (!sku) throw new Error('Seeded SKU PHONE-001 not found');

    // Ensure weight is non-zero so per_weight rates produce a non-zero amount (useful for shipping-method assertions).
    await skuRepo.update({ id: sku.id } as any, { weight: '1' } as any);

    const kenya = await locationRepo.findOne({ where: { type: LocationType.COUNTRY, countryCode: 'KE' } });
    expect(kenya).toBeDefined();
    if (!kenya) throw new Error('Seeded Kenya location not found');

    const registerRes = await request(app.getHttpServer())
      .post('/auth/customer/register')
      .send({
        phone: '+254700000999',
        password: 'Str0ngP@ssw0rd',
        email: 'checkout-e2e@example.com',
        firstName: 'Checkout',
        lastName: 'E2E',
      })
      .expect(201);

    const accessToken = registerRes.body?.data?.accessToken;
    expect(typeof accessToken).toBe('string');

    const authHeader = { Authorization: `Bearer ${accessToken}` };

    const createRes = await request(app.getHttpServer())
      .post('/checkout/sessions')
      .set(authHeader)
      .send({
        orderItems: [{ productSkuId: sku.id, quantity: 1 }],
        currencyCode: 'KES',
      })
      .expect(201);

    const sessionId = createRes.body?.data?.id;
    expect(typeof sessionId).toBe('string');

    await request(app.getHttpServer())
      .put(`/checkout/sessions/${sessionId}/delivery`)
      .set(authHeader)
      .send({
        shippingAddress: {
          countryCode: 'KE',
          locationId: kenya.id,
          firstName: 'Checkout',
          lastName: 'E2E',
          phone: '+254700000999',
          fields: { line1: 'Test street' },
        },
      })
      .expect(200);

    // Delivery is persisted as the customer's shipping address
    const customerAddrRes = await request(app.getHttpServer())
      .get('/customer/shipping-address')
      .set(authHeader)
      .expect(200);

    expect(customerAddrRes.body?.data?.address?.locationId).toBe(kenya.id);

    const methodsRes = await request(app.getHttpServer())
      .get(`/checkout/sessions/${sessionId}/shipping-methods`)
      .set(authHeader)
      .expect(200);

    const quotes = methodsRes.body?.data?.quotes;
    expect(Array.isArray(quotes)).toBe(true);
    expect(quotes.length).toBeGreaterThan(0);

    const express = quotes.find((q: any) => q?.method?.code === 'express') ?? quotes[0];
    const methodCode = express?.method?.code;
    expect(typeof methodCode).toBe('string');

    await request(app.getHttpServer())
      .put(`/checkout/sessions/${sessionId}/shipping-method`)
      .set(authHeader)
      .send({ shippingMethodCode: methodCode })
      .expect(200);

    const reviewRes = await request(app.getHttpServer())
      .get(`/checkout/sessions/${sessionId}/review`)
      .set(authHeader)
      .expect(200);

    expect(reviewRes.body?.data?.shippingMethodCode).toBe(methodCode);

    const confirmRes = await request(app.getHttpServer())
      .post(`/checkout/sessions/${sessionId}/confirm`)
      .set(authHeader)
      .send({})
      .expect(201);

    const order = confirmRes.body?.data?.order;
    expect(order?.id).toBeDefined();

    // DB session is marked completed
    const dbSession = await sessionRepo.findOne({ where: { id: sessionId } });
    expect(dbSession).toBeDefined();
    expect(dbSession!.status).toBe('completed');

    // confirm is not idempotent
    await request(app.getHttpServer())
      .post(`/checkout/sessions/${sessionId}/confirm`)
      .set(authHeader)
      .send({})
      .expect(400);
  }, 60000);

  it('rejects unauthenticated access', async () => {
    await request(app.getHttpServer()).post('/checkout/sessions').send({ orderItems: [] }).expect(401);
  });
});
