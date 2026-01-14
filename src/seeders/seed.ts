import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module';
import { AuthSeeder } from '../auth/seeders/auth.seeder';
import { SettingSeeder } from '../setting/seeders/setting.seeder';
import { OAuthProviderSettingSeeder } from '../setting/seeders/oauth-provider-setting.seeder';
import { CatalogSeeder } from '../catalog/seeders/catalog.seeder';
import { CollectionSeeder } from '../catalog/seeders/collection.seeder';
import { ShippingSeeder } from '../shipping/seeders/shipping.seeder';
import { LocationSeeder } from '../location/seeders/location.seeder';
import { ChannelsSeeder } from '../channels/seeders/channels.seeder';
import { CustomerTierSeeder } from '../customer-tier/seeders/customer-tier.seeder';
import { WhatsappTemplateSeeder } from '../whatsapp/seeders/whatsapp-template.seeder';
import { CurrencySeeder } from '../currency/seeders/currency.seeder';
import { PaymentProviderSeeder } from '../payment-provider/seeders/payment-provider.seeder';
import { PaymentMethodSeeder } from '../payment-method/seeders/payment-method.seeder';

async function runSeeders() {
  console.log('🌱 Starting database seeding...');

  const app = await NestFactory.createApplicationContext(AppModule);

  try {
    const authSeeder = app.get(AuthSeeder);
    const settingSeeder = app.get(SettingSeeder);
    const oauthProviderSettingSeeder = app.get(OAuthProviderSettingSeeder);
    const catalogSeeder = app.get(CatalogSeeder);
    const collectionSeeder = app.get(CollectionSeeder);
    const shippingSeeder = app.get(ShippingSeeder);
    const locationSeeder = app.get(LocationSeeder);
    const channelsSeeder = app.get(ChannelsSeeder);
    const customerTierSeeder = app.get(CustomerTierSeeder);
    const whatsappTemplateSeeder = app.get(WhatsappTemplateSeeder);
    const currencySeeder = app.get(CurrencySeeder);
    const paymentProviderSeeder = app.get(PaymentProviderSeeder);
    const paymentMethodSeeder = app.get(PaymentMethodSeeder);

    console.log('⚙️ Seeding application settings...');
    await settingSeeder.seed();

    console.log('✅ Settings seeding completed');

    console.log('💱 Seeding currencies (KES, USD, EUR, ...)...');
    await currencySeeder.seed();

    console.log('✅ Currencies seeding completed');

    console.log('🗺️ Seeding locations (Kenya)...');
    await locationSeeder.seed();

    console.log('✅ Locations seeding completed');

    console.log('📡 Seeding channels (WEB, MOBILE, WHATSAPP)...');
    await channelsSeeder.seed();

    console.log('✅ Channels seeding completed');

    console.log(
      '💳 Seeding payment providers & methods (Safaricom / M-Pesa)...',
    );
    await paymentProviderSeeder.seed();
    await paymentMethodSeeder.seed();

    console.log('✅ Payments seeding completed');

    console.log(
      '💬 Seeding WhatsApp templates (order success, customer registration)...',
    );
    await whatsappTemplateSeeder.seed();

    console.log('✅ WhatsApp templates seeding completed');

    console.log('🏷️ Seeding customer tiers (BASE)...');
    await customerTierSeeder.seed();

    console.log('✅ Customer tiers seeding completed');

    console.log(
      '📝 Seeding authentication data (roles, permissions, users)...',
    );
    await authSeeder.seed();

    console.log('✅ Authentication seeding completed');

    console.log('🔐 Seeding OAuth provider profiles (Google)...');
    await oauthProviderSettingSeeder.seed();

    console.log('✅ OAuth provider profiles seeding completed');

    console.log('🗂️ Seeding catalog data...');
    await catalogSeeder.seed();

    console.log('🧺 Seeding default collections (Deal Of The Day, New Arrivals)...');
    await collectionSeeder.seed();

    console.log('✅ Collections seeding completed');

    console.log('🚚 Seeding shipping data...');
    try {
      await shippingSeeder.seed();

      console.log('✅ Shipping seeding completed');
    } catch {
      console.warn(
        '⚠️ Shipping seeder skipped/unavailable in this environment',
      );
    }

    console.log('🎉 All seeders completed successfully!');
  } catch (error) {
    console.error('❌ Seeding failed:', error);
    process.exit(1);
  } finally {
    await app.close();
  }
}

runSeeders().catch((error) => {
  console.error('❌ Fatal error during seeding:', error);
  process.exit(1);
});
