import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CustomerShippingAddress } from '../entities/customer-shipping-address.entity';
import { AddressService } from '../../address/services/address.service';
import { UpsertAddressDto } from '../../address/dto/upsert-address.dto';

@Injectable()
export class CustomerShippingAddressService {
  constructor(
    @InjectRepository(CustomerShippingAddress)
    private readonly customerShippingAddressRepo: Repository<CustomerShippingAddress>,
    private readonly addressService: AddressService,
  ) {}

  async getForUser(userId: string) {
    const row = await this.customerShippingAddressRepo.findOne({
      where: { userId },
      relations: ['address'],
    });
    if (!row)
      throw new NotFoundException('Customer shipping address not found');
    return row;
  }

  async getOptionalForUser(userId: string) {
    return this.customerShippingAddressRepo.findOne({
      where: { userId },
      relations: ['address'],
    });
  }

  async upsertForUser(userId: string, payload: UpsertAddressDto) {
    if (!payload?.countryCode) {
      throw new BadRequestException('countryCode is required');
    }

    const existing = await this.customerShippingAddressRepo.findOne({
      where: { userId },
      relations: ['address'],
    });

    if (existing) {
      await this.addressService.update(existing.addressId, payload);
      return this.getForUser(userId);
    }

    const createdAddress = await this.addressService.create(payload);

    const created = await this.customerShippingAddressRepo.save(
      this.customerShippingAddressRepo.create({
        userId,
        addressId: createdAddress.id,
      }),
    );

    return this.customerShippingAddressRepo.findOne({
      where: { id: created.id },
      relations: ['address'],
    });
  }
}
