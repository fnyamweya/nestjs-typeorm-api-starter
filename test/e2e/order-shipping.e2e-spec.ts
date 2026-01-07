import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ProductSku } from '../../src/catalog/entities/product-sku.entity';
import { Order } from '../../src/order/entities/order.entity';
import { OrderLevelCharge } from '../../src/order/entities/order-level-charge.entity';
import { createTestApp, truncateDb } from '../e2e/bootstrap';
import { Location, LocationType } from '../../src/location/entities/location.entity';
import { User } from '../../src/user/entities/user.entity';

describe('Order Shipping E2E', () => {
  let app: INestApplication;
  let skuRepo: Repository<ProductSku>;
  let orderRepo: Repository<Order>;
  let chargeRepo: Repository<OrderLevelCharge>;
  let locationRepo: Repository<Location>;
  let userRepo: Repository<User>;
  let jwtService: JwtService;
  let adminToken: string;

  beforeAll(async () => {
    try {
      const t = await createTestApp();
      app = t.app;
      await truncateDb(t.ds);

      // run seeders necessary for the test
      const settingSeeder = app.get(require('../../src/setting/seeders/setting.seeder').SettingSeeder);
      const locationSeeder = app.get(require('../../src/location/seeders/location.seeder').LocationSeeder);
      const channelsSeeder = app.get(require('../../src/channels/seeders/channels.seeder').ChannelsSeeder);
      const authSeeder = app.get(require('../../src/auth/seeders/auth.seeder').AuthSeeder);
      const catalogSeeder = app.get(require('../../src/catalog/seeders/catalog.seeder').CatalogSeeder);
      const shippingSeeder = app.get(require('../../src/shipping/seeders/shipping.seeder').ShippingSeeder);

      await settingSeeder.seed();
      await locationSeeder.seed();
      await channelsSeeder.seed();
      await authSeeder.seed();
      await catalogSeeder.seed();
      await shippingSeeder.seed();

      skuRepo = app.get(getRepositoryToken(ProductSku));
      orderRepo = app.get(getRepositoryToken(Order));
      chargeRepo = app.get(getRepositoryToken(OrderLevelCharge));
      locationRepo = app.get(getRepositoryToken(Location));
      userRepo = app.get(getRepositoryToken(User));

      jwtService = app.get(JwtService);
      const admin = await userRepo.findOne({ where: { email: 'admin@example.com' } });
      if (!admin) throw new Error('Seeded admin user not found');
      adminToken = jwtService.sign({ sub: admin.id, userId: admin.id, roleId: (admin as any).roleId ?? '' } as any);
    } catch (err) {
      console.error('beforeAll failed in Order Shipping E2E', err);
      throw err;
    }
  }, 120000);

  afterAll(async () => {
    try {
      if (app) await app.close();
    } catch (err) {
      console.error('afterAll failed in Order Shipping E2E', err);
      throw err;
    }
  });

  it('creates an order and applies shipping + tax charges', async () => {
    const sku = await skuRepo.findOne({ where: { sku: 'PHONE-001' } });
    expect(sku).toBeDefined();
    if (!sku) throw new Error('SKU not found');

    await skuRepo.update({ id: sku.id } as any, { weight: '1' } as any);

    const kenya = await locationRepo.findOne({ where: { type: LocationType.COUNTRY, countryCode: 'KE' } });
    expect(kenya).toBeDefined();

    let customer = await userRepo.findOne({ where: { email: 'buyer@example.com' } });
    if (!customer) {
      customer = await userRepo.save(userRepo.create({ email: 'buyer@example.com', phone: '254700000011' } as any) as any);
    }

    if (!customer) throw new Error('Customer not found');

    const payload = {
      customerId: customer.id,
      orderItems: [{ productSkuId: sku!.id, quantity: 1 }],
      shippingLocationId: kenya!.id,
      shippingMethodCode: 'express',
    };

    const res = await request(app.getHttpServer())
      .post('/orders')
      .set('Authorization', `Bearer ${adminToken}`)
      .send(payload)
      .expect(201);
    const body = res.body;
    expect(body).toBeDefined();
    const orderId = body.data?.id || body.id;
    expect(orderId).toBeDefined();

    // Get order from DB and verify charges
    const order = await orderRepo.findOne({ where: { id: orderId } });
    expect(order).toBeDefined();

    const charges = await chargeRepo.find({ where: { orderId: orderId } });
    // should include shipping and tax
    const shippingCharge = charges.find((c) => c.chargeKind === 'shipping');
    const taxCharge = charges.find((c) => c.chargeKind === 'tax');

    expect(shippingCharge).toBeDefined();
    expect(shippingCharge!.amount).toBeDefined();
    expect(parseFloat(shippingCharge!.amount)).toBeGreaterThan(0);

    expect(taxCharge).toBeDefined();
    expect(parseFloat(taxCharge!.amount)).toBeGreaterThan(0);

    expect(parseFloat(order!.grandTotal)).toBeGreaterThan(0);
  });
});
