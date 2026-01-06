import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CountryConfigService } from './country-config.service';
import { CountryConfigController } from './controllers/country-config.controller';
import { CountryConfig } from './entities/country-config.entity';
import { CurrencyModule } from 'src/currency/currency.module';

@Module({
  imports: [TypeOrmModule.forFeature([CountryConfig]), CurrencyModule],
  controllers: [CountryConfigController],
  providers: [CountryConfigService],
  exports: [CountryConfigService, TypeOrmModule],
})
export class CountryModule {}
