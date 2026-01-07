import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Role } from 'src/auth/entities/role.entity';
import { CustomerProfile } from './entities/customer-profile.entity';
import { AdminProfile } from './entities/admin-profile.entity';
import { UserService } from './services/user.service';
import { UserController } from './controllers/user.controller';
import { CustomerController } from './controllers/customer.controller';
import { AuthModule } from 'src/auth/auth.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, Role, CustomerProfile, AdminProfile]),
    AuthModule,
  ],
  providers: [UserService],
  controllers: [UserController, CustomerController],
  exports: [UserService],
})
export class UserModule {}
