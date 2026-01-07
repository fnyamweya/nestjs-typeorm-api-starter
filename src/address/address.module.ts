import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Address } from './entities/address.entity';
import { AddressService } from './services/address.service';
import { AddressFieldConfig } from './entities/address-field-config.entity';
import { AddressFieldConfigService } from './services/address-field-config.service';
import { AddressFieldConfigController } from './controllers/address-field-config.controller';
import { GooglePlacesModule } from 'src/common/google-places/google-places.module';
import { CountryModule } from 'src/country/country.module';
import { Location } from 'src/location/entities/location.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([Address, AddressFieldConfig, Location]),
    GooglePlacesModule,
    CountryModule,
  ],
  controllers: [AddressFieldConfigController],
  providers: [AddressService, AddressFieldConfigService],
  exports: [AddressService, AddressFieldConfigService, TypeOrmModule],
})
export class AddressModule {}
