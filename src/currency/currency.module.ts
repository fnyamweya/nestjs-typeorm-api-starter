import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Currency } from '../catalog/entities/currency.entity';
import { CurrencyController } from './currency.controller';
import { CurrencyService } from './currency.service';
import { CurrencySeeder } from './seeders/currency.seeder';

@Module({
  imports: [TypeOrmModule.forFeature([Currency])],
  controllers: [CurrencyController],
  providers: [CurrencyService, CurrencySeeder],
  exports: [CurrencyService, CurrencySeeder],
})
export class CurrencyModule {}
