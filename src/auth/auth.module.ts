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
import { UserAuthProvider } from './entities/user-auth-provider.entity';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { AppleStrategy } from './strategies/apple.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { OptionalJwtAuthGuard } from './guards/optional-jwt-auth.guard';
import { PermissionsGuard } from './guards/permissions.guard';
import { RolesGuard } from './guards/roles.guard';
import { User } from 'src/user/entities/user.entity';
import { AuthController } from './controllers/auth.controller';
import { PublicAuthController } from './controllers/public-auth.controller';
import { UserActivityLog } from 'src/activity-log/entities/user-activity-log.entity';
import { Setting } from 'src/setting/entities/setting.entity';
import { OAuthProviderSetting } from 'src/setting/entities/oauth-provider-setting.entity';
import { AuthSeeder } from './seeders/auth.seeder';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';
import { SmsServiceUtils } from 'src/common/utils/sms-service.utils';
import { CustomerProfile } from 'src/user/entities/customer-profile.entity';
import { AdminProfile } from 'src/user/entities/admin-profile.entity';
import { UserInvite } from './entities/user-invite.entity';
import { WhatsappModule } from 'src/whatsapp/whatsapp.module';
import { AuthOtpWorkerService } from './workers/auth-otp.worker';
import { OAuthCredentialsService } from './services/oauth-credentials.service';
import { OAuthExchangeService } from './services/oauth-exchange.service';
import { GoogleOAuthGuard } from './guards/google-oauth.guard';
import { AppleOAuthGuard } from './guards/apple-oauth.guard';

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
      UserAuthProvider,
      UserInvite,
      Setting,
      OAuthProviderSetting,
      CustomerProfile,
      AdminProfile,
    ]),
    WhatsappModule,
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
    AuthOtpWorkerService,
    OAuthCredentialsService,
    OAuthExchangeService,
    GoogleOAuthGuard,
    AppleOAuthGuard,
    EmailServiceUtils,
    SmsServiceUtils,
    JwtStrategy,
    GoogleStrategy,
    AppleStrategy,
    JwtAuthGuard,
    OptionalJwtAuthGuard,
    PermissionsGuard,
    RolesGuard,
    AuthSeeder,
  ],
  controllers: [AuthController, PublicAuthController, RoleController],
  exports: [
    AuthService,
    RoleService,
    TwoFactorService,
    EmailServiceUtils,
    JwtAuthGuard,
    OptionalJwtAuthGuard,
    PermissionsGuard,
    RolesGuard,
  ],
})
export class AuthModule {}
