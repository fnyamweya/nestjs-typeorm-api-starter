import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CustomerTier } from './entities/customer-tier.entity';
import { CustomerTierRule } from './entities/customer-tier-rule.entity';
import { CustomerTierService } from './customer-tier.service';
import { CustomerTierController } from './customer-tier.controller';
import { CustomerProfile } from 'src/user/entities/customer-profile.entity';
import { User } from 'src/user/entities/user.entity';
import { Order } from 'src/order/entities/order.entity';
import { CustomerTierSeeder } from './seeders/customer-tier.seeder';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      CustomerTier,
      CustomerTierRule,
      CustomerProfile,
      User,
      Order,
    ]),
  ],
  controllers: [CustomerTierController],
  providers: [CustomerTierService, CustomerTierSeeder],
  exports: [CustomerTierService, CustomerTierSeeder, TypeOrmModule],
})
export class CustomerTierModule {}
