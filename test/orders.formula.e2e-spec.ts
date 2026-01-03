import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { SettingSeeder } from '../src/setting/seeders/setting.seeder';
import { CatalogSeeder } from '../src/catalog/seeders/catalog.seeder';
import { ShippingSeeder } from '../src/shipping/seeders/shipping.seeder';
import { DataSource } from 'typeorm';
import { ShippingZone } from '../src/shipping/entities/shipping-zone.entity';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ProductVariant } from '../src/catalog/entities/product-variant.entity';
import { OrderLevelCharge } from '../src/order/entities/order-level-charge.entity';
import { ShippingMethod } from '../src/shipping/entities/shipping-method.entity';
import { ShippingRate } from '../src/shipping/entities/shipping-rate.entity';
import { Location, LocationType } from '../src/location/entities/location.entity';
import { User } from '../src/user/entities/user.entity';

async function createTestApp() {
  const moduleFixture = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  const app = moduleFixture.createNestApplication();
  await app.init();

  const ds = app.get(DataSource);
  return { app, ds };
}

async function truncateDb(dataSource: DataSource) {
  const entities = dataSource.entityMetadatas;
  for (const entity of entities) {
    const repository = dataSource.getRepository(entity.name);
    await repository.query(`TRUNCATE TABLE "${entity.tableName}" CASCADE`);
  }
}

describe('Orders E2E - Formula shipping integration', () => {
  let app: INestApplication;
  let variantRepo: Repository<ProductVariant>;
  let chargeRepo: Repository<OrderLevelCharge>;
  let methodRepo: Repository<ShippingMethod>;
  let rateRepo: Repository<ShippingRate>;
  let locationRepo: Repository<Location>;
  let userRepo: Repository<User>;
  let ds: DataSource;
  let kenyaZone: ShippingZone | undefined;
  let kenyaLocationId: string;

  beforeAll(async () => {
    try {
      const t = await createTestApp();
      app = t.app;
      ds = t.ds;

      await truncateDb(ds);

      // Run seeders (settings, catalog, shipping)
      const settingSeeder = app.get(require('../src/setting/seeders/setting.seeder').SettingSeeder);
      const catalogSeeder = app.get(require('../src/catalog/seeders/catalog.seeder').CatalogSeeder);
      const shippingSeeder = app.get(require('../src/shipping/seeders/shipping.seeder').ShippingSeeder);
      const locationSeeder = app.get(require('../src/location/seeders/location.seeder').LocationSeeder);

      try {
        await settingSeeder.seed();
        await locationSeeder.seed();
        await catalogSeeder.seed();
        await shippingSeeder.seed();
      } catch (err) {
        console.error('Seeder failed during e2e setup', err);
        throw err;
      }

      variantRepo = app.get(getRepositoryToken(ProductVariant));
      chargeRepo = app.get(getRepositoryToken(OrderLevelCharge));
      methodRepo = app.get(getRepositoryToken(ShippingMethod));
      rateRepo = app.get(getRepositoryToken(ShippingRate));
      locationRepo = app.get(getRepositoryToken(Location));
      userRepo = app.get(getRepositoryToken(User));

      const kenya = await locationRepo.findOne({ where: { type: LocationType.COUNTRY, countryCode: 'KE' } });
      if (!kenya) throw new Error('Kenya location not found after seeding');
      kenyaLocationId = kenya.id;

      // Ensure we have the Kenya zone and use it explicitly for the formula method
      const zone = (await ds.query(`SELECT * FROM shipping_zone WHERE code = 'kenya' LIMIT 1`))[0];
      if (!zone) throw new Error('Kenya shipping zone not found after seeding');
      kenyaZone = zone as any;
    } catch (err) {
      console.error('beforeAll failed in Orders Formula E2E', err);
      throw err;
    }
  }, 120000);

  afterAll(async () => {
    await app.close();
  });

  it('creates an order using a formula rate and persists expected shipping charge', async () => {
    const variant = await variantRepo.findOne({ where: { sku: 'PHONE-001' } });
    expect(variant).toBeDefined();
    if (!variant) throw new Error('Variant not found');

    // Create a high-priority formula method/rate for Kenya
    if (!kenyaZone) throw new Error('Kenya zone not available');
    const m = methodRepo.create({ zoneId: kenyaZone.id, code: 'formula-method', displayName: 'Formula Shipping' });
    const savedMethod = await methodRepo.save(m);

    const r = rateRepo.create({ methodId: savedMethod.id, calculationType: 'formula', price: '0', priority: 100, metaJson: { formula: 'subtotal * 0.05' } });
    await rateRepo.save(r);

    // sanity check: ensure ShippingMatrixService returns expected quote for KE
    const shippingMatrixService = app.get(require('../src/shipping/services/shipping-matrix.service').ShippingMatrixService);

    // Set variant weight so per_weight routes produce non-zero amounts and priority tie-breakers favor formula
    await variantRepo.update({ sku: 'PHONE-001' } as any, { weight: '1' } as any);

    const quotes = await shippingMatrixService.getQuotes({ locationId: kenyaLocationId, subtotal: 400, totalWeight: 1, itemCount: 2, currencyCode: 'KES' });
    expect(quotes.length).toBeGreaterThan(0);
    expect(quotes[0].method.code).toBe('formula-method');
    expect(quotes[0].amount).toBeCloseTo(400 * 0.05, 6);

    let customer = await userRepo.findOne({ where: { email: 'e2e-formula@example.com' } });
    if (!customer) {
      customer = await userRepo.save(userRepo.create({ email: 'e2e-formula@example.com', phone: '254700000012' } as any) as any);
    }

    const payload = {
      customerId: customer.id,
      orderItems: [{ productVariantId: variant.id, quantity: 2 }],
      shippingLocationId: kenyaLocationId,
    };

    const res = await request(app.getHttpServer()).post('/orders').send(payload).expect(201);
    const createdOrder = res.body.data;

    const charges = await chargeRepo.find({ where: { orderId: createdOrder.id } });
    const shippingCharges = charges.filter((c) => c.chargeKind === 'shipping');
    expect(shippingCharges.length).toBeGreaterThan(0);

    // subtotal = 200*2 = 400; formula = subtotal * 0.05 = 20
    const shipping = shippingCharges.find((s) => s.sourceReference === 'formula-method');
    expect(shipping).toBeDefined();
    expect(Number(shipping!.amount)).toBeCloseTo(20, 2);
  }, 30000);
});