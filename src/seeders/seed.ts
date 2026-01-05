import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module';
import { AuthSeeder } from '../auth/seeders/auth.seeder';
import { SettingSeeder } from '../setting/seeders/setting.seeder';
import { CatalogSeeder } from '../catalog/seeders/catalog.seeder';
import { ShippingSeeder } from '../shipping/seeders/shipping.seeder';
import { LocationSeeder } from '../location/seeders/location.seeder';
import { ChannelsSeeder } from '../channels/seeders/channels.seeder';
import { CustomerTierSeeder } from '../customer-tier/seeders/customer-tier.seeder';
import { WhatsappTemplateSeeder } from '../whatsapp/seeders/whatsapp-template.seeder';

async function runSeeders() {
  // eslint-disable-next-line no-console
  console.log('🌱 Starting database seeding...');

  const app = await NestFactory.createApplicationContext(AppModule);

  try {
    const authSeeder = app.get(AuthSeeder);
    const settingSeeder = app.get(SettingSeeder);
    const catalogSeeder = app.get(CatalogSeeder);
    const shippingSeeder = app.get(ShippingSeeder);
    const locationSeeder = app.get(LocationSeeder);
    const channelsSeeder = app.get(ChannelsSeeder);
    const customerTierSeeder = app.get(CustomerTierSeeder);
    const whatsappTemplateSeeder = app.get(WhatsappTemplateSeeder);

    // eslint-disable-next-line no-console
    console.log('⚙️ Seeding application settings...');
    await settingSeeder.seed();
    // eslint-disable-next-line no-console
    console.log('✅ Settings seeding completed');

    // eslint-disable-next-line no-console
    console.log('🗺️ Seeding locations (Kenya)...');
    await locationSeeder.seed();
    // eslint-disable-next-line no-console
    console.log('✅ Locations seeding completed');

    // eslint-disable-next-line no-console
    console.log('📡 Seeding channels (WEB, MOBILE, WHATSAPP)...');
    await channelsSeeder.seed();
    // eslint-disable-next-line no-console
    console.log('✅ Channels seeding completed');

    // eslint-disable-next-line no-console
    console.log('💬 Seeding WhatsApp templates (order success, customer registration)...');
    await whatsappTemplateSeeder.seed();
    // eslint-disable-next-line no-console
    console.log('✅ WhatsApp templates seeding completed');

    // eslint-disable-next-line no-console
    console.log('🏷️ Seeding customer tiers (BASE)...');
    await customerTierSeeder.seed();
    // eslint-disable-next-line no-console
    console.log('✅ Customer tiers seeding completed');

    // eslint-disable-next-line no-console
    console.log('📝 Seeding authentication data (roles, permissions, users)...');
    await authSeeder.seed();
    // eslint-disable-next-line no-console
    console.log('✅ Authentication seeding completed');

    // eslint-disable-next-line no-console
    console.log('🗂️ Seeding catalog data...');
    await catalogSeeder.seed();

    // eslint-disable-next-line no-console
    console.log('🚚 Seeding shipping data...');
    try {
      await shippingSeeder.seed();
      // eslint-disable-next-line no-console
      console.log('✅ Shipping seeding completed');
    } catch {
      // eslint-disable-next-line no-console
      console.warn('⚠️ Shipping seeder skipped/unavailable in this environment');
    }

    // eslint-disable-next-line no-console
    console.log('🎉 All seeders completed successfully!');
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error('❌ Seeding failed:', error);
    process.exit(1);
  } finally {
    await app.close();
  }
}

runSeeders().catch((error) => {
  // eslint-disable-next-line no-console
  console.error('❌ Fatal error during seeding:', error);
  process.exit(1);
});
