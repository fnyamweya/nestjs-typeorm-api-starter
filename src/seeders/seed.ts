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
  console.log('🌱 Starting database seeding...');

  const app = await NestFactory.createApplicationContext(AppModule);

  try {
    // Get seeder instances
    const authSeeder = app.get(AuthSeeder);
    const settingSeeder = app.get(SettingSeeder);
    const catalogSeeder = app.get(CatalogSeeder);
      const shippingSeeder = app.get(ShippingSeeder);
    const locationSeeder = app.get(LocationSeeder);
    const channelsSeeder = app.get(ChannelsSeeder);
    const customerTierSeeder = app.get(CustomerTierSeeder);
    const whatsappTemplateSeeder = app.get(WhatsappTemplateSeeder);

    // Run seeders in order
    console.log('⚙️ Seeding application settings...');
    await settingSeeder.seed();
    console.log('✅ Settings seeding completed');

    console.log('🗺️ Seeding locations (Kenya)...');
    await locationSeeder.seed();
    console.log('✅ Locations seeding completed');

    console.log('📡 Seeding channels (WEB, MOBILE, WHATSAPP)...');
    await channelsSeeder.seed();
    console.log('✅ Channels seeding completed');

    console.log('💬 Seeding WhatsApp templates (order success, customer registration)...');
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

    console.log('🗂️ Seeding catalog data...');
    await catalogSeeder.seed();
    console.log('🚚 Seeding shipping data...');
    try {
      await shippingSeeder.seed();
      console.log('✅ Shipping seeding completed');
    } catch (err) {
      console.warn('⚠️ Shipping seeder skipped/unavailable in this environment');
    }
    console.log('✅ Catalog seeding completed');

    console.log('🎉 All seeders completed successfully!');
  } catch (error) {
    console.error('❌ Seeding failed:', error);
    process.exit(1);
  } finally {
    await app.close();
  }
}

// Run the seeder
runSeeders().catch((error) => {
  console.error('❌ Fatal error during seeding:', error);
  process.exit(1);
});
