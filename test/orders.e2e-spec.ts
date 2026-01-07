import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ProductSku } from '../src/catalog/entities/product-sku.entity';
import { OrderLevelCharge } from '../src/order/entities/order-level-charge.entity';
import { createTestApp, truncateDb } from './e2e/bootstrap';
import { Location, LocationType } from '../src/location/entities/location.entity';
import { User } from '../src/user/entities/user.entity';


describe('Orders E2E - Shipping integration', () => {
  let app: INestApplication;
  let skuRepo: Repository<ProductSku>;
  let chargeRepo: Repository<OrderLevelCharge>;
  let locationRepo: Repository<Location>;
  let userRepo: Repository<User>;
  let jwtService: JwtService;
  let adminToken: string;

  beforeAll(async () => {
    try {
      const t = await createTestApp();
      app = t.app;

      // ensure a clean DB and run seeders via existing seed entrypoint
      await truncateDb(t.ds);
      const settingSeeder = app.get(require('../src/setting/seeders/setting.seeder').SettingSeeder);
      const channelsSeeder = app.get(require('../src/channels/seeders/channels.seeder').ChannelsSeeder);
      const authSeeder = app.get(require('../src/auth/seeders/auth.seeder').AuthSeeder);
      const catalogSeeder = app.get(require('../src/catalog/seeders/catalog.seeder').CatalogSeeder);
      const shippingSeeder = app.get(require('../src/shipping/seeders/shipping.seeder').ShippingSeeder);
      const locationSeeder = app.get(require('../src/location/seeders/location.seeder').LocationSeeder);
      await settingSeeder.seed();
      await locationSeeder.seed();
      await channelsSeeder.seed();
      await authSeeder.seed();
      await catalogSeeder.seed();
      await shippingSeeder.seed();

      skuRepo = app.get(getRepositoryToken(ProductSku));
      chargeRepo = app.get(getRepositoryToken(OrderLevelCharge));
      locationRepo = app.get(getRepositoryToken(Location));
      userRepo = app.get(getRepositoryToken(User));

      jwtService = app.get(JwtService);
      const admin = await userRepo.findOne({ where: { email: 'admin@example.com' } });
      if (!admin) throw new Error('Seeded admin user not found');
      adminToken = jwtService.sign({ sub: admin.id, userId: admin.id, roleId: (admin as any).roleId ?? '' } as any);
    } catch (err) {
      console.error('beforeAll failed in Orders E2E', err);
      throw err;
    }
  }, 120000);

  afterAll(async () => {
    try {
      if (app) await app.close();
    } catch (err) {
      console.error('afterAll failed closing app in Orders E2E', err);
      throw err;
    }
  });

  it('creates an order and persists shipping and tax charges', async () => {
    const sku = await skuRepo.findOne({ where: { sku: 'PHONE-001' } });
    expect(sku).toBeDefined();
    if (!sku) throw new Error('SKU not found');

    // Ensure per_weight express rate produces a non-zero shipping charge
    await skuRepo.update({ id: sku.id } as any, { weight: '1' } as any);

    const kenya = await locationRepo.findOne({ where: { type: LocationType.COUNTRY, countryCode: 'KE' } });
    expect(kenya).toBeDefined();

    const existingCustomer = await userRepo.findOne({ where: { email: 'e2e@example.com' } });
    const customer =
      existingCustomer ??
      (await userRepo.save(userRepo.create({ email: 'e2e@example.com', phone: '254700000010' } as any) as any));

    const payload = {
      customerId: customer.id,
      orderItems: [{ productSkuId: sku.id, quantity: 1 }],
      shippingLocationId: kenya!.id,
      shippingMethodCode: 'express',
    };

    const res = await request(app.getHttpServer())
      .post('/orders')
      .set('Authorization', `Bearer ${adminToken}`)
      .send(payload)
      .expect(201);

    const createdOrder = res.body.data;
    expect(createdOrder).toBeDefined();
    expect(createdOrder.itemsSubtotal).toBeDefined();

    // Fetch order level charges
    const charges = await chargeRepo.find({ where: { orderId: createdOrder.id } });
    // Expect shipping and tax charges (no discount for this subtotal)
    const shippingCharges = charges.filter((c) => c.chargeKind === 'shipping');
    const taxCharges = charges.filter((c) => c.chargeKind === 'tax');

    expect(shippingCharges.length).toBeGreaterThan(0);
    expect(taxCharges.length).toBeGreaterThan(0);

    // Keep assertions resilient to price seeding changes
    expect(parseFloat(createdOrder.itemsSubtotal)).toBeGreaterThan(0);
    expect(parseFloat(createdOrder.grandTotal)).toBeGreaterThan(0);
    const shipping = shippingCharges[0];
    expect(parseFloat(shipping.amount)).toBeGreaterThan(0);
  }, 20000);
});
