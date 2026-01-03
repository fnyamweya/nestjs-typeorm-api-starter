import dataSource from '../data-source';

async function runSeeders() {
  console.log('🌱 Starting database seeding...');
  let exitCode = 0;

  try {
    if (!dataSource.isInitialized) {
      await dataSource.initialize();
    }

    // Minimal baseline seed to keep db:reset working during ongoing refactors.
    // NOTE: This intentionally avoids Nest application context and service-level seeders.
    console.log('💱 Ensuring default currency (KES)...');
    await dataSource.query(
      `INSERT INTO "currency" ("code", "symbol", "precision") VALUES ('KES', 'KSh', 2)
       ON CONFLICT ("code") DO NOTHING;`,
    );

    console.log('📋 Ensuring default price list (DEFAULT)...');
    await dataSource.query(
      `INSERT INTO "price_list" ("code", "name", "currency_code", "is_active") VALUES ('DEFAULT', 'Default', 'KES', true)
       ON CONFLICT ("code") DO NOTHING;`,
    );

    console.log('🎉 All seeders completed successfully!');
  } catch (error) {
    console.error('❌ Seeding failed:', error);
    exitCode = 1;
  } finally {
    try {
      if (dataSource.isInitialized) {
        await dataSource.destroy();
      }
    } finally {
      process.exit(exitCode);
    }
  }
}

// Run the seeder
runSeeders().catch((error) => {
  console.error('❌ Fatal error during seeding:', error);
  process.exit(1);
});
