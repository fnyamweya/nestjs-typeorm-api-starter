import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CustomerAddress } from '../entities/customer-address.entity';
import {
  CUSTOMER_ADDRESS_TYPES,
  CustomerAddressType,
} from '../customer-address.types';
import { AddressService } from '../../address/services/address.service';
import { UpsertAddressDto } from '../../address/dto/upsert-address.dto';

@Injectable()
export class CustomerAddressService {
  constructor(
    @InjectRepository(CustomerAddress)
    private readonly customerAddressRepo: Repository<CustomerAddress>,
    private readonly addressService: AddressService,
  ) {}

  async listForUser(userId: string) {
    return this.customerAddressRepo.find({
      where: { userId },
      relations: ['address'],
      order: { createdAt: 'DESC' },
    });
  }

  async getForUserByType(userId: string, type: CustomerAddressType) {
    if (!CUSTOMER_ADDRESS_TYPES.includes(type)) {
      throw new BadRequestException('Invalid address type');
    }

    const row = await this.customerAddressRepo.findOne({
      where: { userId, type },
      relations: ['address'],
    });

    if (!row) throw new NotFoundException('Address not found');
    return row;
  }

  async upsertForUser(
    userId: string,
    type: CustomerAddressType,
    address: UpsertAddressDto,
  ) {
    if (!CUSTOMER_ADDRESS_TYPES.includes(type)) {
      throw new BadRequestException('Invalid address type');
    }

    const existing = await this.customerAddressRepo.findOne({
      where: { userId, type },
      relations: ['address'],
    });

    if (existing) {
      await this.addressService.update(existing.addressId, address);
      return this.getForUserByType(userId, type);
    }

    const total = await this.customerAddressRepo.count({ where: { userId } });
    if (total >= 3) {
      throw new BadRequestException('You can only save up to 3 addresses');
    }

    const createdAddress = await this.addressService.create(address);

    const created = await this.customerAddressRepo.save(
      this.customerAddressRepo.create({
        userId,
        type,
        addressId: createdAddress.id,
      }),
    );

    return this.customerAddressRepo.findOne({
      where: { id: created.id },
      relations: ['address'],
    });
  }

  async deleteForUserByType(userId: string, type: CustomerAddressType) {
    const existing = await this.customerAddressRepo.findOne({
      where: { userId, type },
    });
    if (!existing) return { deleted: false };

    // Cascades will delete address row too.
    const res = await this.customerAddressRepo.delete(existing.id);
    return { deleted: (res.affected || 0) > 0 };
  }
}
