import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './services/auth.service';
import { RoleService } from './services/role.service';
import { TwoFactorService } from './services/two-factor.service';
import { RoleController } from './controllers/role.controller';
import { Role } from './entities/role.entity';
import { Permission } from './entities/permission.entity';
import { RolePermission } from './entities/role-permission.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { CacheKey } from './entities/cache-key.entity';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { PermissionsGuard } from './guards/permissions.guard';
import { RolesGuard } from './guards/roles.guard';
import { User } from 'src/user/entities/user.entity';
import { AuthController } from './controllers/auth.controller';
import { UserActivityLog } from 'src/activity-log/entities/user-activity-log.entity';
import { Setting } from 'src/setting/entities/setting.entity';
import { AuthSeeder } from './seeders/auth.seeder';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      User,
      Role,
      Permission,
      RolePermission,
      RefreshToken,
      UserActivityLog,
      CacheKey,
      Setting,
    ]),
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRATION', '15m'),
        },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [
    AuthService,
    RoleService,
    TwoFactorService,
    EmailServiceUtils,
    JwtStrategy,
    JwtAuthGuard,
    PermissionsGuard,
    RolesGuard,
    AuthSeeder,
  ],
  controllers: [AuthController, RoleController],
  exports: [
    AuthService,
    RoleService,
    TwoFactorService,
    EmailServiceUtils,
    JwtAuthGuard,
    PermissionsGuard,
    RolesGuard,
  ],
})
export class AuthModule {}
