import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module';
import { DataSource } from 'typeorm';

async function clearDatabase() {
  console.log('🧹 Starting database cleanup...');

  const app = await NestFactory.createApplicationContext(AppModule);
  const dataSource = app.get(DataSource);

  try {
    const truncateMode = true;

    if (truncateMode) {
      console.log('🗑️ Truncating all tables...');

      // Get all table names
      const tables = await dataSource.query(`
        SELECT tablename FROM pg_tables 
        WHERE schemaname = 'public' 
        AND tablename NOT LIKE 'pg_%' 
        AND tablename != 'information_schema'
      `);

      // Disable foreign key checks temporarily
      await dataSource.query('SET session_replication_role = replica;');

      // Truncate all tables
      for (const table of tables) {
        await dataSource.query(`TRUNCATE TABLE "${table.tablename}" CASCADE;`);
        console.log(`✅ Truncated table: ${table.tablename}`);
      }

      // Re-enable foreign key checks
      await dataSource.query('SET session_replication_role = DEFAULT;');

      console.log('🎉 All tables truncated successfully!');
    } else {
      console.log('🗑️ Dropping and recreating database schema...');

      // Drop all tables and recreate schema
      await dataSource.dropDatabase();
      await dataSource.synchronize();

      console.log('🎉 Database schema recreated successfully!');
    }
  } catch (error) {
    console.error('❌ Database cleanup failed:', error);
    process.exit(1);
  } finally {
    await app.close();
  }
}

// Run the cleanup
clearDatabase().catch((error) => {
  console.error('❌ Fatal error during cleanup:', error);
  process.exit(1);
});
