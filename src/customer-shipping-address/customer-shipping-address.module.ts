import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CustomerShippingAddress } from './entities/customer-shipping-address.entity';
import { CustomerShippingAddressService } from './services/customer-shipping-address.service';
import { CustomerShippingAddressController } from './controllers/customer-shipping-address.controller';
import { AddressModule } from '../address/address.module';

@Module({
  imports: [TypeOrmModule.forFeature([CustomerShippingAddress]), AddressModule],
  providers: [CustomerShippingAddressService],
  controllers: [CustomerShippingAddressController],
  exports: [CustomerShippingAddressService],
})
export class CustomerShippingAddressModule {}
