import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Role } from 'src/auth/entities/role.entity';
import { CustomerProfile } from './entities/customer-profile.entity';
import { AdminProfile } from './entities/admin-profile.entity';
import { UserService } from './services/user.service';
import { UserController } from './controllers/user.controller';

@Module({
  imports: [TypeOrmModule.forFeature([User, Role, CustomerProfile, AdminProfile])],
  providers: [UserService],
  controllers: [UserController],
  exports: [UserService],
})
export class UserModule {}
