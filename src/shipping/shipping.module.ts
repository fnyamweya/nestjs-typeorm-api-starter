import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ShippingZone } from './entities/shipping-zone.entity';
import { ShippingZoneLocation } from './entities/shipping-zone-location.entity';
import { ShippingMethod } from './entities/shipping-method.entity';
import { ShippingRate } from './entities/shipping-rate.entity';
import { ShippingZoneMethod } from './entities/shipping-zone-method.entity';
import { ShippingProvider } from './entities/shipping-provider.entity';
import { ShippingMatrixService } from './services/shipping-matrix.service';
import { ShippingSeeder } from './seeders/shipping.seeder';
import { SettingModule } from '../setting/setting.module';
import { AdminShippingController } from './controllers/admin-shipping.controller';
import { ShippingAdminService } from './services/shipping-admin.service';
import { Location } from '../location/entities/location.entity';
import { CatalogModule } from '../catalog/catalog.module';
import { CatalogShippingContextService } from './services/catalog-shipping-context.service';
import { ShippingController } from './controllers/shipping.controller';
import { ShippingQuotesService } from './services/shipping-quotes.service';
import { CurrencyModule } from '../currency/currency.module';
import { Channel } from '../channels/entities/channel.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      ShippingZone,
      ShippingZoneLocation,
      ShippingMethod,
      ShippingZoneMethod,
      ShippingProvider,
      ShippingRate,
      Location,
      Channel,
    ]),
    SettingModule,
    CatalogModule,
    CurrencyModule,
  ],
  controllers: [AdminShippingController, ShippingController],
  providers: [
    ShippingMatrixService,
    ShippingSeeder,
    ShippingAdminService,
    CatalogShippingContextService,
    ShippingQuotesService,
  ],
  exports: [
    ShippingMatrixService,
    ShippingSeeder,
    ShippingAdminService,
    CatalogShippingContextService,
    ShippingQuotesService,
  ],
})
export class ShippingModule {}
