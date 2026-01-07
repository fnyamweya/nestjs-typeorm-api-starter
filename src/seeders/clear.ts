import baseDataSource from '../data-source';
import { DataSource } from 'typeorm';

const dataSource = new DataSource({
  ...(baseDataSource.options as any),
  // db:clear should never modify schema; only truncate data.
  migrationsRun: false,
  synchronize: false,
  logging: false,
});

async function clearDatabase() {
  console.log('🧹 Starting database cleanup...');

  let exitCode = 0;

  try {
    if (!dataSource.isInitialized) {
      await dataSource.initialize();
    }

    console.log('🗑️ Truncating all tables...');

    // Get all table names
    const tables: Array<{ tablename: string }> = await dataSource.query(`
      SELECT tablename FROM pg_tables 
      WHERE schemaname = 'public' 
      AND tablename NOT LIKE 'pg_%' 
      AND tablename NOT IN ('information_schema', 'migrations', 'typeorm_metadata')
    `);

    if (!tables.length) {
      console.log('ℹ️ No tables found to truncate.');
      return;
    }

    // Use TRUNCATE ... CASCADE to safely clear tables without superuser privileges
    const tableList = tables.map((t) => `"${t.tablename}"`).join(', ');

    await dataSource.query(`TRUNCATE TABLE ${tableList} CASCADE;`);
    console.log('🎉 All tables truncated successfully!');
  } catch (error) {
    console.error('❌ Database cleanup failed:', error);
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

// Run the cleanup
clearDatabase().catch((error) => {
  console.error('❌ Fatal error during cleanup:', error);
  process.exit(1);
});
