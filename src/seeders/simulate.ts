import { NestFactory } from '@nestjs/core';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AppModule } from '../app.module';
import { SettingSeeder } from '../setting/seeders/setting.seeder';
import { CatalogSeeder } from '../catalog/seeders/catalog.seeder';
import { ShippingSeeder } from '../shipping/seeders/shipping.seeder';
import { OrderService } from '../order/services/order.service';
import { ProductSku } from '../catalog/entities/product-sku.entity';
import { Order } from '../order/entities/order.entity';
import { MpesaService } from '../mpesa/services/mpesa.service';
import { LocationSeeder } from '../location/seeders/location.seeder';
import { Location, LocationType } from '../location/entities/location.entity';
import { User } from '../user/entities/user.entity';
import { ChannelsSeeder } from '../channels/seeders/channels.seeder';
import { PaymentProviderSeeder } from '../payment-provider/seeders/payment-provider.seeder';
import { PaymentMethodSeeder } from '../payment-method/seeders/payment-method.seeder';

const SIM_ORDER_EXTERNAL_ID = 'SIM-ORDER-001';
const SIM_MPESA_TX_ID = 'SIMTX-001';
const SIM_CUSTOMER_EMAIL = 'simulate@example.com';
const SIM_CUSTOMER_PHONE = '254700000001';

async function runSimulationSeed() {
  console.log('🧪 Starting simulation seed (order + mpesa payment)...');

  const app = await NestFactory.createApplicationContext(AppModule);

  try {
    const settingSeeder = app.get(SettingSeeder);
    const catalogSeeder = app.get(CatalogSeeder);
    const shippingSeeder = app.get(ShippingSeeder);
    const locationSeeder = app.get(LocationSeeder);
    const channelsSeeder = app.get(ChannelsSeeder);
    const paymentProviderSeeder = app.get(PaymentProviderSeeder);
    const paymentMethodSeeder = app.get(PaymentMethodSeeder);

    const orderService = app.get(OrderService);
    const mpesaService = app.get(MpesaService);

    const skuRepo = app.get<Repository<ProductSku>>(
      getRepositoryToken(ProductSku),
    );
    const orderRepo = app.get<Repository<Order>>(getRepositoryToken(Order));
    const locationRepo = app.get<Repository<Location>>(
      getRepositoryToken(Location),
    );
    const userRepo = app.get<Repository<User>>(getRepositoryToken(User));

    // Ensure base data exists
    await settingSeeder.seed();
    await locationSeeder.seed();
    await channelsSeeder.seed();

    await paymentProviderSeeder.seed();
    await paymentMethodSeeder.seed();
    await catalogSeeder.seed();
    try {
      await shippingSeeder.seed();
    } catch {
      // ignore (some envs may not have shipping tables)
    }

    const sku = await skuRepo.findOne({ where: { sku: 'PHONE-001' } });
    if (!sku) {
      throw new Error(
        'Missing seeded product SKU PHONE-001. Run db:seed first or check CatalogSeeder.',
      );
    }

    // Idempotent-ish: reuse the same simulated order if it exists
    let order = await orderRepo.findOne({
      where: { externalId: SIM_ORDER_EXTERNAL_ID },
    });

    // Find/create a simulation customer
    let customer: User | null = await userRepo.findOne({
      where: { email: SIM_CUSTOMER_EMAIL },
    });
    if (!customer) {
      const created = userRepo.create({
        email: SIM_CUSTOMER_EMAIL,
        phone: SIM_CUSTOMER_PHONE,
        firstName: 'Simulation',
        lastName: 'Customer',
        isActive: true,
        isBanned: false,
      } as any);

      customer = (await userRepo.save(created as any)) as User;
    }

    if (!customer) {
      throw new Error('Failed to create or load simulation customer user');
    }

    const kenya = await locationRepo.findOne({
      where: { type: LocationType.COUNTRY, countryCode: 'KE' },
    });
    if (!kenya) {
      throw new Error(
        'Missing Kenya country location. Run LocationSeeder.seed() and verify location data.',
      );
    }

    if (!order) {
      order = await orderService.create({
        customerId: customer.id,
        orderItems: [{ productSkuId: sku.id, quantity: 2 }],
        shippingLocationId: kenya.id,
      });

      await orderRepo.update(
        { id: order.id } as any,
        {
          externalId: SIM_ORDER_EXTERNAL_ID,
          notesInternal: 'Created by simulation seeder',
          metaJson: { ...(order.metaJson || {}), seed: 'simulation' },
        } as any,
      );

      order = (await orderRepo.findOne({ where: { id: order.id } })) ?? order;
    }

    const amount = Number(order.grandTotal || '0');

    // Simulate a C2B confirmation callback that will auto-link via BillRefNumber -> order.orderNumber
    await mpesaService.handleC2BConfirmation({
      TransactionType: 'Pay Bill',
      TransID: SIM_MPESA_TX_ID,
      TransTime: '20260101120000',
      TransAmount: amount,
      BusinessShortCode: '174379',
      BillRefNumber: order.orderNumber,
      InvoiceNumber: '',
      OrgAccountBalance: '0',
      ThirdPartyTransID: '',
      MSISDN: '254700000000',
      FirstName: 'Sim',
      MiddleName: '',
      LastName: 'User',
    });

    console.log('✅ Simulation seed complete');

    console.log(
      `- Order: id=${order.id} externalId=${SIM_ORDER_EXTERNAL_ID} orderNumber=${order.orderNumber} total=${order.grandTotal}`,
    );

    console.log(
      `- Mpesa: transactionId=${SIM_MPESA_TX_ID} billRefNumber=${order.orderNumber}`,
    );
  } catch (error) {
    console.error('❌ Simulation seed failed:', error);
    process.exit(1);
  } finally {
    await app.close();
  }
}

runSimulationSeed().catch((error) => {
  console.error('❌ Fatal error during simulation seed:', error);
  process.exit(1);
});
