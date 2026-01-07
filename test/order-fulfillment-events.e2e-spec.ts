import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { createTestApp, truncateDb } from './e2e/bootstrap';
import { ProductSku } from '../src/catalog/entities/product-sku.entity';
import { Location, LocationType } from '../src/location/entities/location.entity';
import { User } from '../src/user/entities/user.entity';
import { ShippingMethod } from '../src/shipping/entities/shipping-method.entity';

describe('Order Fulfillment + Order Events E2E', () => {
  let app: INestApplication;
  let skuRepo: Repository<ProductSku>;
  let locationRepo: Repository<Location>;
  let userRepo: Repository<User>;
  let shippingMethodRepo: Repository<ShippingMethod>;
  let jwtService: JwtService;
  let adminToken: string;

  beforeAll(async () => {
    const t = await createTestApp();
    app = t.app;

    await truncateDb(t.ds);
    const settingSeeder = app.get(require('../src/setting/seeders/setting.seeder').SettingSeeder);
    const channelsSeeder = app.get(require('../src/channels/seeders/channels.seeder').ChannelsSeeder);
    const authSeeder = app.get(require('../src/auth/seeders/auth.seeder').AuthSeeder);
    const catalogSeeder = app.get(require('../src/catalog/seeders/catalog.seeder').CatalogSeeder);
    const shippingSeeder = app.get(require('../src/shipping/seeders/shipping.seeder').ShippingSeeder);
    await settingSeeder.seed();
    await authSeeder.seed();
    await channelsSeeder.seed();
    await catalogSeeder.seed();

    // Avoid seeding the full Kenya location tree (can be slow in CI). We only need a COUNTRY row for ShippingSeeder.
    locationRepo = app.get(getRepositoryToken(Location));
    const existingKenya = await locationRepo.findOne({ where: { type: LocationType.COUNTRY, countryCode: 'KE' } as any });
    if (!existingKenya) {
      await locationRepo.save(
        locationRepo.create({
          name: 'Kenya',
          type: LocationType.COUNTRY,
          countryCode: 'KE',
          code: 'KE',
        } as any) as any,
      );
    }
    await shippingSeeder.seed();

    skuRepo = app.get(getRepositoryToken(ProductSku));
    userRepo = app.get(getRepositoryToken(User));
    shippingMethodRepo = app.get(getRepositoryToken(ShippingMethod));

    jwtService = app.get(JwtService);
    const admin = await userRepo.findOne({ where: { email: 'admin@example.com' } });
    if (!admin) throw new Error('Seeded admin user not found');

    adminToken = jwtService.sign({ sub: admin.id, userId: admin.id, roleId: (admin as any).roleId ?? '' } as any);
  }, 180000);

  afterAll(async () => {
    if (app) await app.close();
  });

  it('creates fulfillment, updates status, and logs events with idempotency keys', async () => {
    const sku = await skuRepo.findOne({ where: { sku: 'PHONE-001' } });
    expect(sku).toBeDefined();
    if (!sku) throw new Error('SKU not found');

    // Ensure shipping matrix has weight to compute shipping
    await skuRepo.update({ id: sku.id } as any, { weight: '1' } as any);

    const kenya = await locationRepo.findOne({ where: { type: LocationType.COUNTRY, countryCode: 'KE' } });
    expect(kenya).toBeDefined();
    if (!kenya) throw new Error('Kenya location not found');

    const existingCustomer = await userRepo.findOne({ where: { email: 'e2e-fulfillment@example.com' } });
    const customer =
      existingCustomer ??
      (await userRepo.save(userRepo.create({ email: 'e2e-fulfillment@example.com', phone: '254700000011' } as any) as any));

    const orderCreatePayload = {
      customerId: customer.id,
      orderItems: [{ productSkuId: sku.id, quantity: 1 }],
      shippingLocationId: kenya.id,
      shippingMethodCode: 'express',
    };

    const orderRes = await request(app.getHttpServer())
      .post('/orders')
      .set('Authorization', `Bearer ${adminToken}`)
      .send(orderCreatePayload)
      .expect(201);

    const order = orderRes.body.data;
    expect(order?.id).toBeDefined();

    const hydratedRes = await request(app.getHttpServer())
      .get(`/orders/${order.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    const hydrated = hydratedRes.body.data;
    expect(hydrated?.items?.length).toBeGreaterThan(0);
    const orderItemId = hydrated.items[0].id;

    const shipMethod = await shippingMethodRepo.findOne({ where: { code: 'express' } as any });
    expect(shipMethod).toBeDefined();
    if (!shipMethod) throw new Error('Express shipping method not found');

    const fulfillmentCreatePayload = {
      status: 'SHIPPED',
      shippingMethodId: shipMethod.id,
      tracking: {
        trackingNumber: 'TRK123',
        trackingUrl: 'https://carrier.example/track/TRK123',
      },
      packages: [
        {
          trackingNumber: 'TRK123-1',
          items: [{ orderItemId, quantity: 1 }],
        },
      ],
      timestamps: {
        shippedAt: new Date('2026-01-07T10:05:00Z').toISOString(),
      },
    };

    const fulRes = await request(app.getHttpServer())
      .post(`/orders/${order.id}/fulfillments`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send(fulfillmentCreatePayload)
      .expect(201);

    const fulfillment = fulRes.body.data;
    expect(fulfillment?.id).toBeDefined();
    const fulfillmentId = fulfillment.id;

    expect(Array.isArray(fulfillment.packages)).toBe(true);
    expect(fulfillment.packages.length).toBe(1);
    const packageId = fulfillment.packages[0].packageId;
    expect(packageId).toBeDefined();

    // Basic fulfillment reads
    await request(app.getHttpServer())
      .get(`/orders/${order.id}/fulfillments`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    await request(app.getHttpServer())
      .get(`/orders/${order.id}/fulfillments/${fulfillmentId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    // Update status to DELIVERED
    const deliveredAt = new Date('2026-01-07T12:00:00Z').toISOString();
    await request(app.getHttpServer())
      .patch(`/orders/${order.id}/fulfillments/${fulfillmentId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        status: 'DELIVERED',
        timestamps: { deliveredAt },
      })
      .expect(200);

    // Calling PATCH again with same status should not duplicate due to idempotencyKey uniqueness
    await request(app.getHttpServer())
      .patch(`/orders/${order.id}/fulfillments/${fulfillmentId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'DELIVERED' })
      .expect(200);

    // Fetch events and assert presence
    const eventsRes = await request(app.getHttpServer())
      .get(`/orders/${order.id}/events`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    const events: any[] = eventsRes.body.data;
    expect(Array.isArray(events)).toBe(true);
    expect(events.length).toBeGreaterThan(0);

    const byKey = (key: string) => events.find((e) => e.idempotencyKey === key);
    const keys = events.map((e) => e.idempotencyKey);

    // Fulfillment events
    expect(byKey(`fulfillment:${fulfillmentId}:created`)).toBeDefined();
    const shippedEvent = byKey(`fulfillment:${fulfillmentId}:shipped`);
    expect(shippedEvent).toBeDefined();
    expect(shippedEvent.action).toBe('fulfillment.status.shipped');
    expect(shippedEvent.previous?.action).toBe('fulfillment.created');
    expect(shippedEvent.next?.actions).toContain('fulfillment.status.delivered');

    // Order-level mirror event
    expect(byKey(`order:${order.id}:fulfillment:${fulfillmentId}:shipped`)).toBeDefined();

    // Package events
    expect(byKey(`package:${packageId}:created`)).toBeDefined();
    expect(byKey(`package:${packageId}:fulfillment:${fulfillmentId}:shipped`)).toBeDefined();
    expect(byKey(`package:${packageId}:fulfillment:${fulfillmentId}:delivered`)).toBeDefined();

    // Order item allocation events
    expect(byKey(`order_item:${orderItemId}:fulfillment:${fulfillmentId}:allocated`)).toBeDefined();
    expect(byKey(`package:${packageId}:order_item:${orderItemId}:allocated`)).toBeDefined();

    // Delivered idempotency: only one delivered event per key
    const deliveredKey = `fulfillment:${fulfillmentId}:delivered`;
    expect(keys.filter((k) => k === deliveredKey).length).toBe(1);
  }, 60000);
});
