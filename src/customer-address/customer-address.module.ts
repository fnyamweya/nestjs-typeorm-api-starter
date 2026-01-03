import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CustomerAddress } from './entities/customer-address.entity';
import { CustomerAddressService } from './services/customer-address.service';
import { CustomerAddressController } from './controllers/customer-address.controller';
import { AddressModule } from '../address/address.module';

@Module({
  imports: [TypeOrmModule.forFeature([CustomerAddress]), AddressModule],
  providers: [CustomerAddressService],
  controllers: [CustomerAddressController],
  exports: [CustomerAddressService],
})
export class CustomerAddressModule {}
