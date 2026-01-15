import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AddressModule } from '../address/address.module';
import { Location } from './entities/location.entity';
import { CountryConfig } from 'src/country/entities/country-config.entity';
import { LocationService } from './services/location.service';
import { LocationController } from './controllers/location.controller';
import { LocationSeeder } from './seeders/location.seeder';
import { GooglePlacesModule } from 'src/common/google-places/google-places.module';
import { GoogleLocationsController } from './controllers/google-locations.controller';
import { CountryModule } from 'src/country/country.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Location, CountryConfig]),
    AddressModule,
    GooglePlacesModule,
    CountryModule,
  ],
  providers: [LocationService, LocationSeeder],
  controllers: [LocationController, GoogleLocationsController],
  exports: [LocationService, LocationSeeder, TypeOrmModule],
})
export class LocationModule {}
