import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ShippingZone } from './entities/shipping-zone.entity';
import { ShippingZoneLocation } from './entities/shipping-zone-location.entity';
import { ShippingMethod } from './entities/shipping-method.entity';
import { ShippingRate } from './entities/shipping-rate.entity';
import { ShippingMatrixService } from './services/shipping-matrix.service';
import { ShippingSeeder } from './seeders/shipping.seeder';
import { SettingModule } from '../setting/setting.module';
import { AdminShippingController } from './controllers/admin-shipping.controller';
import { ShippingAdminService } from './services/shipping-admin.service';

@Module({
  imports: [TypeOrmModule.forFeature([ShippingZone, ShippingZoneLocation, ShippingMethod, ShippingRate]), SettingModule],
  controllers: [AdminShippingController],
  providers: [ShippingMatrixService, ShippingSeeder, ShippingAdminService],
  exports: [ShippingMatrixService, ShippingSeeder, ShippingAdminService],
})
export class ShippingModule {}
