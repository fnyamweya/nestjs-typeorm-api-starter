import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, ILike } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { User } from 'src/user/entities/user.entity';
import { RefreshToken } from '../entities/refresh-token.entity';
import { JwtPayload, AuthenticatedUser } from '../interfaces/user.interface';
import {
  ActivityAction,
  UserActivityLog,
} from 'src/activity-log/entities/user-activity-log.entity';
import { Request } from 'express';
import { parseUserAgent } from 'src/common/utils/user-agent.util';
import { TwoFactorService } from './two-factor.service';
import { LoginDto } from '../dto/login.dto';
import { UpdateProfileDto } from '../dto/update-profile.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';
import { ForgotPasswordSendOTPDto } from '../dto/forgot-password-send-otp.dto';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';
import * as crypto from 'crypto';
import {
  CacheKey,
  CacheKeyService,
  CacheKeyStatus,
} from '../entities/cache-key.entity';
import { VerifyPasswordResetOTPCodeDto } from '../dto/verify-password-reset-otp-code.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { SetPasswordDto } from '../dto/set-password.dto';
import { CustomerLoginDto } from '../dto/customer-login.dto';
import { AdminLoginDto } from '../dto/admin-login.dto';
import { CustomerRegisterDto } from '../dto/customer-register.dto';
import { CustomerProfile } from 'src/user/entities/customer-profile.entity';
import { Role } from '../entities/role.entity';
import { AdminRegisterDto } from '../dto/admin-register.dto';
import { AdminProfile } from 'src/user/entities/admin-profile.entity';
import { verifyPassword } from 'src/common/utils/password.util';
import { OAuthAdminProfile } from '../interfaces/oauth-admin-profile.interface';
import { UserAuthProvider } from '../entities/user-auth-provider.entity';
import { UserInvite, UserInviteStatus } from '../entities/user-invite.entity';
import { CreateUserInviteDto } from '../dto/create-user-invite.dto';
import { AcceptUserInviteDto } from '../dto/accept-user-invite.dto';
import { DeclineUserInviteDto } from '../dto/decline-user-invite.dto';
import { AuthProviderType, MfaChannel, UserStatus } from 'src/user/enums';
import { FeatureFlagService } from 'src/feature-flag/feature-flag.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(UserActivityLog)
    private userActivityLogRepository: Repository<UserActivityLog>,
    @InjectRepository(CacheKey)
    private cacheKeyRepository: Repository<CacheKey>,
    @InjectRepository(CustomerProfile)
    private customerProfileRepository: Repository<CustomerProfile>,
    @InjectRepository(AdminProfile)
    private adminProfileRepository: Repository<AdminProfile>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRepository(UserAuthProvider)
    private userAuthProviderRepository: Repository<UserAuthProvider>,
    @InjectRepository(UserInvite)
    private userInviteRepository: Repository<UserInvite>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private twoFactorService: TwoFactorService,
    private s3ClientUtils: S3ClientUtils,
    private emailServiceUtils: EmailServiceUtils,
    private featureFlagService: FeatureFlagService,
  ) {}

  private async ensureAdminProfile(userId: string) {
    const existingProfile = await this.adminProfileRepository.findOne({
      where: { userId },
    });

    if (!existingProfile) {
      await this.adminProfileRepository.save(
        this.adminProfileRepository.create({ userId }),
      );
    }
  }

  async validateUser(email: string, plainPassword: string) {
    const user = await this.userRepository.findOne({
      where: { email },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.isBanned || user.isActive === false) {
      throw new UnauthorizedException('Account is disabled');
    }

    if (!(await this.verifyUserPassword(user, plainPassword))) {
      throw new UnauthorizedException('Invalid password');
    }

    const { passwordHash, ...result } = user;
    void passwordHash;
    return result;
  }

  async validateUserById(id: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { id },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });
  }

  async login(loginDto: LoginDto, request: Request) {
    const user = await this.validateUser(loginDto.email, loginDto.password);

    // Check if 2FA is enabled for this user
    const is2FAEnabled = await this.twoFactorService.isTwoFactorEnabled(
      user.id,
    );

    if (is2FAEnabled) {
      await this.twoFactorService.sendVerificationCode(user.id);

      return {
        requiresTwoFactor: true,
        userId: user.id,
        message: 'Two-factor authentication code sent to your email',
      };
    }

    const fullUser = await this.userRepository.findOne({
      where: { id: user.id },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });

    if (!fullUser) {
      throw new UnauthorizedException('User not found');
    }

    return this.completeLogin(fullUser, request);
  }

  async registerCustomer(
    customerRegisterDto: CustomerRegisterDto,
    request: Request,
  ) {
    const existingByPhone = await this.userRepository.findOne({
      where: { phone: customerRegisterDto.phone },
    });

    if (existingByPhone) {
      throw new BadRequestException('Phone number is already registered');
    }

    if (customerRegisterDto.email) {
      const existingByEmail = await this.userRepository.findOne({
        where: { email: customerRegisterDto.email },
      });
      if (existingByEmail) {
        throw new BadRequestException('Email is already registered');
      }
    }

    const customerRole = await this.roleRepository.findOne({
      where: [{ name: 'customer' }, { name: ILike('customer') }],
    });

    if (!customerRole) {
      throw new BadRequestException('Customer role is not configured');
    }

    const user = this.userRepository.create({
      email: customerRegisterDto.email,
      phone: customerRegisterDto.phone,
      firstName: customerRegisterDto.firstName,
      lastName: customerRegisterDto.lastName,
      roleId: customerRole.id,
      authProvider: AuthProviderType.LOCAL,
      isActive: true,
      status: UserStatus.ACTIVE,
      mfaChannel: MfaChannel.EMAIL,
      twoFactorEnabled: false,
    });
    user.passwordHash = customerRegisterDto.password;

    const savedUser = await this.userRepository.save(user);

    await this.userAuthProviderRepository.save(
      this.userAuthProviderRepository.create({
        userId: savedUser.id,
        provider: 'local',
        providerId: savedUser.id,
      }),
    );

    const profile = this.customerProfileRepository.create({
      userId: savedUser.id,
    });
    await this.customerProfileRepository.save(profile);

    return this.completeLogin(savedUser, request);
  }

  async registerAdmin(adminRegisterDto: AdminRegisterDto, request: Request) {
    const existingByEmail = await this.userRepository.findOne({
      where: { email: adminRegisterDto.email },
    });

    if (existingByEmail) {
      throw new BadRequestException('Email is already registered');
    }

    if (adminRegisterDto.phone) {
      const existingByPhone = await this.userRepository.findOne({
        where: { phone: adminRegisterDto.phone },
      });
      if (existingByPhone) {
        throw new BadRequestException('Phone number is already registered');
      }
    }

    const adminRole = await this.roleRepository.findOne({
      where: [{ name: 'admin' }, { name: ILike('admin') }],
    });

    if (!adminRole) {
      throw new BadRequestException('Admin role is not configured');
    }

    const user = this.buildAdminUserEntity(adminRegisterDto, adminRole);
    const savedUser = await this.userRepository.save(user);

    await this.userAuthProviderRepository.save(
      this.userAuthProviderRepository.create({
        userId: savedUser.id,
        provider: 'local',
        providerId: savedUser.id,
      }),
    );

    await this.ensureAdminProfile(savedUser.id);

    return this.completeLogin(savedUser, request);
  }

  async createUserInvite(
    createUserInviteDto: CreateUserInviteDto,
    inviter: AuthenticatedUser,
  ) {
    const inviterRole = inviter.role?.name || '';

    const email = createUserInviteDto.email.trim().toLowerCase();
    const phone = createUserInviteDto.phone.trim();

    const pendingInvite = await this.userInviteRepository.findOne({
      where: { email, status: UserInviteStatus.PENDING },
    });

    if (pendingInvite) {
      pendingInvite.status = UserInviteStatus.EXPIRED;
      await this.userInviteRepository.save(pendingInvite);
      if (pendingInvite.userId) {
        const pendingUser = await this.userRepository.findOne({ where: { id: pendingInvite.userId } });
        if (pendingUser && !pendingUser.isActive) {
          await this.userRepository.remove(pendingUser);
        }
      }
    }

    const existingUser = await this.userRepository.findOne({ where: { email } });
    if (existingUser) {
      throw new BadRequestException('A user with this email already exists');
    }

    const existingPhoneUser = await this.userRepository.findOne({ where: { phone } });
    if (existingPhoneUser) {
      throw new BadRequestException('A user with this phone already exists');
    }

    const adminRole = await this.roleRepository.findOne({
      where: [{ name: 'admin' }, { name: ILike('admin') }],
    });

    const requestedRoleId = createUserInviteDto.roleId || adminRole?.id;

    if (!requestedRoleId) {
      throw new BadRequestException('Target role is required');
    }

    const targetRole = await this.roleRepository.findOne({ where: { id: requestedRoleId } });
    if (!targetRole) {
      throw new BadRequestException('Target role not found');
    }

    await this.assertInviterCanAssignRole(inviter.roleId, requestedRoleId, inviterRole);

    const roleId = requestedRoleId;
    const expiresInDays = parseInt(
      this.configService.get<string>('USER_INVITE_EXPIRY_DAYS', '7'),
      10,
    );
    const expiresAt = new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000);

    // Create placeholder user that will activate upon password set
    const pendingUser = await this.userRepository.save(
      this.userRepository.create({
        email,
        phone,
        firstName: createUserInviteDto.firstName,
        lastName: createUserInviteDto.lastName,
        roleId,
        authProvider: AuthProviderType.LOCAL,
        isActive: false,
        status: UserStatus.DISABLED,
        mfaChannel: MfaChannel.EMAIL,
        twoFactorEnabled: false,
      }),
    );

    const token = crypto.randomUUID();
    const tokenHash = this.hashToken(token);

    await this.cacheKeyRepository.save(
      this.cacheKeyRepository.create({
        userId: pendingUser.id,
        service: CacheKeyService.SET_PASSWORD,
        code: tokenHash,
        expiresAt,
        status: CacheKeyStatus.PENDING,
        attempts: 0,
        maxAttempts: 1,
      }),
    );

    const invite = await this.userInviteRepository.save(
      this.userInviteRepository.create({
        email,
        firstName: createUserInviteDto.firstName,
        lastName: createUserInviteDto.lastName,
        invitedBy: inviter.id,
        roleId,
        token,
        status: UserInviteStatus.PENDING,
        expiresAt,
        userId: pendingUser.id,
      }),
    );

    const appUrl = this.configService.get<string>('APP_URL', 'http://localhost:3000');
    const passwordSetPath = this.configService.get<string>(
      'PASSWORD_SET_PATH',
      '/auth/password-set',
    );
    const base = appUrl.endsWith('/') ? appUrl.slice(0, -1) : appUrl;
    const inviteLink = `${base}${passwordSetPath}?token=${invite.token}`;

    await this.emailServiceUtils.sendSetPasswordLink({
      email,
      link: inviteLink,
      appName: this.configService.get<string>('APP_NAME', 'Application'),
      expiresInMinutes: Math.round((expiresAt.getTime() - Date.now()) / 60000),
    });

    return {
      token: invite.token,
      expiresAt: invite.expiresAt,
    };
  }

  async acceptUserInvite(
    acceptUserInviteDto: AcceptUserInviteDto,
    request: Request,
  ) {
    const updatedUser = await this.completePasswordSetup(
      { token: acceptUserInviteDto.token, newPassword: acceptUserInviteDto.password },
      request,
    );

    return this.completeLogin(updatedUser, request);
  }

  async declineUserInvite(declineUserInviteDto: DeclineUserInviteDto) {
    const invite = await this.userInviteRepository.findOne({
      where: { token: declineUserInviteDto.token },
    });

    if (!invite) {
      throw new BadRequestException('Invitation not found');
    }

    if (invite.status !== UserInviteStatus.PENDING) {
      throw new BadRequestException('Invitation is no longer valid');
    }

    invite.status = UserInviteStatus.DECLINED;
    invite.declinedAt = new Date();
    await this.userInviteRepository.save(invite);

    const tokenHash = this.hashToken(declineUserInviteDto.token);
    const cacheKey = await this.cacheKeyRepository.findOne({
      where: {
        code: tokenHash,
        service: CacheKeyService.SET_PASSWORD,
        status: CacheKeyStatus.PENDING,
      },
    });

    if (cacheKey) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
    }

    if (invite.userId) {
      const placeholderUser = await this.userRepository.findOne({ where: { id: invite.userId } });
      if (placeholderUser && !placeholderUser.isActive) {
        await this.userRepository.remove(placeholderUser);
      }
    }

    return { declined: true };
  }

  private async assertInviterCanAssignRole(
    inviterRoleId: string | undefined,
    targetRoleId: string,
    inviterRoleName?: string,
  ) {
    if (!inviterRoleId) {
      throw new ForbiddenException('Inviter role is required');
    }

    const treeRepo = this.roleRepository.manager.getTreeRepository(Role);
    const inviterRole = await treeRepo.findOne({
      where: { id: inviterRoleId },
      relations: ['parent'],
    });

    if (inviterRole?.name?.toLowerCase() === 'super admin') {
      return; // Super Admin can invite any role
    }

    const targetRole = await treeRepo.findOne({
      where: { id: targetRoleId },
      relations: ['parent'],
    });

    if (!targetRole) {
      throw new BadRequestException('Target role not found');
    }

    const ancestors = await treeRepo.findAncestors(targetRole);
    const isAllowed = ancestors.some((r) => r.id === inviterRoleId);

    if (!isAllowed) {
      throw new ForbiddenException(
        `Role ${inviterRoleName || inviterRoleId} cannot invite into role ${targetRole.name}`,
      );
    }
  }

  async loginCustomer(
    customerLoginDto: CustomerLoginDto,
    request: Request,
  ) {
    const user = await this.userRepository.findOne({
      where: [
        { email: customerLoginDto.identifier },
        { phone: customerLoginDto.identifier },
      ],
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });

    const isCustomer = user?.role?.name?.toLowerCase() === 'customer';

    if (!user || !isCustomer) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.isBanned || user.isActive === false) {
      throw new UnauthorizedException('Account is disabled');
    }

    if (
      !(await this.verifyUserPassword(user, customerLoginDto.password))
    ) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const is2FAEnabled = await this.twoFactorService.isTwoFactorEnabled(
      user.id,
    );

    if (is2FAEnabled) {
      await this.twoFactorService.sendVerificationCode(user.id);

      return {
        requiresTwoFactor: true,
        userId: user.id,
        message: 'Two-factor authentication code sent to your email',
      };
    }

    return this.completeLogin(user, request);
  }

  async loginAdmin(adminLoginDto: AdminLoginDto, request: Request) {
    const user = await this.userRepository.findOne({
      where: { email: adminLoginDto.email },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });

    const isAdminOrSuper =
      user?.role?.name?.toLowerCase() === 'admin' ||
      user?.role?.name?.toLowerCase() === 'super admin';

    if (!user || !isAdminOrSuper) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.isBanned || user.isActive === false) {
      throw new UnauthorizedException('Account is disabled');
    }

    if (!(await this.verifyUserPassword(user, adminLoginDto.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const env = this.configService.get<string>('NODE_ENV', 'development');
    const isSuperAdmin = user.role?.name?.toLowerCase() === 'super admin';
    if (isSuperAdmin && env === 'development') {
      const shouldBypass2FA = await this.featureFlagService.isEnabled(
        'auth.super_admin_skip_2fa',
        {
          userId: user.id,
          roles: user.role?.name ? [user.role.name] : [],
          env,
        },
      );

      if (shouldBypass2FA) {
        await this.ensureAdminProfile(user.id);
        return this.completeLogin(user, request);
      }
    }

    const is2FAEnabled = await this.twoFactorService.isTwoFactorEnabled(
      user.id,
    );

    if (!is2FAEnabled) {
      await this.twoFactorService.sendVerificationCode(user.id);
      return {
        requiresTwoFactor: true,
        userId: user.id,
        message: 'Two-factor authentication code sent to your email',
      };
    }

    if (!adminLoginDto.twoFactorCode) {
      await this.twoFactorService.sendVerificationCode(user.id);
      return {
        requiresTwoFactor: true,
        userId: user.id,
        message: 'Two-factor authentication code sent to your email',
      };
    }

    const isValidCode = await this.twoFactorService.validateLoginCode(
      user.id,
      adminLoginDto.twoFactorCode,
    );

    if (!isValidCode) {
      throw new UnauthorizedException('Invalid or expired verification code');
    }

    await this.ensureAdminProfile(user.id);

    return this.completeLogin(user, request);
  }

  async loginAdminWithOAuth(
    oauthProfile: OAuthAdminProfile,
    request: Request,
  ) {
    if (!oauthProfile?.email) {
      throw new UnauthorizedException(
        'OAuth provider did not supply an email address',
      );
    }

    const normalizedEmail = oauthProfile.email.toLowerCase();

    const relations: string[] = [
      'role',
      'role.rolePermissions',
      'role.rolePermissions.permission',
    ];

    const linkedByProvider = await this.userAuthProviderRepository.findOne({
      where: {
        provider: oauthProfile.provider,
        providerId: oauthProfile.providerId,
      },
      relations: ['user', 'user.role', 'user.role.rolePermissions', 'user.role.rolePermissions.permission'],
    });

    let user: User | undefined;

    if (linkedByProvider?.user) {
      user = linkedByProvider.user;
    } else {
      user =
        (await this.userRepository.findOne({
          where: { email: normalizedEmail },
          relations,
        })) || undefined;
    }

    const adminRole = await this.roleRepository.findOne({
      where: [{ name: 'admin' }, { name: ILike('admin') }],
    });

    if (!adminRole) {
      throw new BadRequestException('Admin role is not configured');
    }

    const ensureAdminProfile = async (userId: string) => {
      const existingProfile = await this.adminProfileRepository.findOne({
        where: { userId },
      });

      if (!existingProfile) {
        const profile = this.adminProfileRepository.create({ userId });
        await this.adminProfileRepository.save(profile);
      }
    };
    const provider =
      oauthProfile.provider === 'apple'
        ? AuthProviderType.APPLE
        : AuthProviderType.GOOGLE;

    if (!user) {
      const generatedPhone = `oauth-${oauthProfile.provider}-${oauthProfile.providerId}`;

      user = this.userRepository.create({
        email: normalizedEmail,
        phone: generatedPhone,
        firstName: oauthProfile.firstName,
        lastName: oauthProfile.lastName,
        roleId: adminRole.id,
        authProvider: provider,
        isActive: true,
        status: UserStatus.ACTIVE,
        mfaChannel: MfaChannel.EMAIL,
      });

      user = await this.userRepository.save(user);
      await this.userAuthProviderRepository.save(
        this.userAuthProviderRepository.create({
          userId: user.id,
          provider,
          providerId: oauthProfile.providerId,
        }),
      );
      await ensureAdminProfile(user.id);
    } else {
      const isAdmin =
        user.role?.name?.toLowerCase() === 'admin' || user.roleId === adminRole.id;

      if (!isAdmin) {
        throw new UnauthorizedException('Account is not authorized as admin');
      }

      if (user.isBanned || user.isActive === false) {
        throw new UnauthorizedException('Account is disabled');
      }

      user.authProvider = provider;
      user.firstName = user.firstName || oauthProfile.firstName;
      user.lastName = user.lastName || oauthProfile.lastName;

      await this.userRepository.save(user);
      const existingLink = await this.userAuthProviderRepository.findOne({
        where: {
          provider: oauthProfile.provider,
          providerId: oauthProfile.providerId,
        },
      });

      if (!existingLink) {
        await this.userAuthProviderRepository.save(
          this.userAuthProviderRepository.create({
            userId: user.id,
            provider: oauthProfile.provider,
            providerId: oauthProfile.providerId,
          }),
        );
      }
      await ensureAdminProfile(user.id);
    }

    const hydratedUser = await this.userRepository.findOne({
      where: { id: user.id },
      relations,
    });

    if (!hydratedUser) {
      throw new UnauthorizedException('Unable to load admin account');
    }

    return this.completeLogin(hydratedUser, request);
  }

  async verifyTwoFactorAndLogin(
    userId: string,
    code: string,
    request: Request,
  ) {
    // Validate the 2FA code
    const isValidCode = await this.twoFactorService.validateLoginCode(
      userId,
      code,
    );

    if (!isValidCode) {
      throw new UnauthorizedException('Invalid or expired verification code');
    }

    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (user.isBanned || user.isActive === false) {
      throw new UnauthorizedException('Account is disabled');
    }

    // Complete the login process
    return this.completeLogin(user, request);
  }

  private async completeLogin(user: User, request: Request) {
    const payload: JwtPayload = {
      sub: user.id,
      userId: user.id,
      roleId: user.role?.id ?? user.roleId ?? '',
    };

    const accessToken = this.jwtService.sign(payload);
    // Revoke all previous refresh token here
    await this.revokeAllUserTokens(user.id);

    const refreshToken = await this.generateRefreshToken(user.id);

    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      isActivityLog: true,
      action: ActivityAction.LOGIN,
      description: `User logged in successfully`,
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    await this.userRepository.update(user.id, {
      lastLoginAt: new Date().toISOString(),
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshAccessToken(refreshTokenString: string) {
    const refreshToken = await this.refreshTokenRepository.findOne({
      where: { token: refreshTokenString, isRevoked: false },
      relations: [
        'user',
        'user.role',
        'user.role.rolePermissions',
        'user.role.rolePermissions.permission',
      ],
    });

    if (!refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (refreshToken.expiresAt < new Date()) {
      // Revoke the refresh token
      refreshToken.isRevoked = true;
      await this.refreshTokenRepository.save(refreshToken);

      throw new UnauthorizedException(
        'Expired refresh token! Please login again',
      );
    }

    const payload: JwtPayload = {
      sub: refreshToken.user.id,
      userId: refreshToken.user.id,
      roleId: refreshToken.user?.role?.id,
    };

    const accessToken = this.jwtService.sign(payload);

    return {
      accessToken,
      accessTokenExpiresAt: this.configService.get<string>(
        'JWT_EXPIRATION',
        '15m',
      ),
      user: {
        id: refreshToken.user.id,
      },
    };
  }

  async logout(refreshTokenString: string) {
    const refreshToken = await this.refreshTokenRepository.findOne({
      where: { token: refreshTokenString },
    });

    if (refreshToken) {
      refreshToken.isRevoked = true;
      await this.refreshTokenRepository.save(refreshToken);
    }
  }

  async revokeAllUserTokens(userId: string) {
    await this.refreshTokenRepository.update(
      { userId, isRevoked: false },
      { isRevoked: true },
    );
  }

  private async generateRefreshToken(userId: string): Promise<string> {
    const token = this.jwtService.sign(
      { sub: userId },
      {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get<string>(
          'JWT_REFRESH_EXPIRATION',
          '7d',
        ),
      },
    );

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    const refreshToken = this.refreshTokenRepository.create({
      token,
      userId,
      expiresAt,
    });

    await this.refreshTokenRepository.save(refreshToken);
    return token;
  }

  async updateProfile(
    userId: string,
    updateProfileDto: UpdateProfileDto,
    request: Request,
    profileImage?: Express.Multer.File | null,
  ) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Update user fields
    Object.assign(user, updateProfileDto);

    if (profileImage) {
      // Delete previous profile image from S3
      if (
        user.profileImageUrl &&
        (await this.s3ClientUtils.objectExists(user.profileImageUrl))
      ) {
        await this.s3ClientUtils.deleteObject(user.profileImageUrl);
      }

      // Upload new profile image to S3
      const { key: profileImageUploadedKey } =
        await this.s3ClientUtils.uploadFile({
          key: `${profileImage.originalname}-${new Date().getTime()}`,
          body: profileImage.buffer,
          contentType: profileImage.mimetype,
          path: 'userProfile',
        });

      user.profileImageUrl = profileImageUploadedKey || '';
    }

    const updatedUser = await this.userRepository.save(user);

    // Log activity
    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.UPDATE,
      description: 'User profile updated successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    const { passwordHash, ...result } = updatedUser;
    void passwordHash;
    return result;
  }

  async changePassword(
    userId: string,
    changePasswordDto: ChangePasswordDto,
    request: Request,
  ): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify current password
    if (
      !(await this.verifyUserPassword(user, changePasswordDto.currentPassword))
    ) {
      throw new BadRequestException('Current password is incorrect');
    }

    // Update password
    user.password = changePasswordDto.newPassword;
    await this.userRepository.save(user);

    // Revoke all refresh tokens for security
    await this.revokeAllUserTokens(userId);

    // Log activity
    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.UPDATE,
      description: 'User password changed successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    await this.userActivityLogRepository.save(userActivityLog);
  }

  async deleteProfile(userId: string, request: Request): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: ['refreshTokens', 'twoFactorAuth'],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Log activity before deletion
    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.DELETE,
      description: 'User account deleted successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    // Revoke all refresh tokens
    await this.revokeAllUserTokens(userId);

    await this.userRepository.remove(user);
  }

  async passwordResetOTPSend(
    forgotPasswordSendOTP: ForgotPasswordSendOTPDto,
    request: Request,
  ) {
    const user = await this.userRepository.findOne({
      where: { email: forgotPasswordSendOTP.email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Log activity
    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.FORGOT_PASSWORD_SEND_OTP,
      description: 'User send forgot password request',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    // Generate verification code
    const code = this.generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Create cache key record
    const cacheKey = this.cacheKeyRepository.create({
      userId: user.id,
      service: CacheKeyService.RESET_PASSWORD,
      code,
      expiresAt,
      status: CacheKeyStatus.PENDING,
      attempts: 0,
      maxAttempts: 3,
    });
    await this.cacheKeyRepository.save(cacheKey);

    // Send Forgot password reset code
    const displayName =
      [user.firstName, user.lastName].filter(Boolean).join(' ').trim() ||
      user.email ||
      user.phone;

    await this.emailServiceUtils.sendForgotPasswordResetCode({
      code,
      email: user.email,
      userName: displayName,
      fromUsername: this.configService.get<string>('EMAIL_FROM_NAME', ''),
      expiresIn: 10,
    });

    return {
      userId: user.id,
    };
  }

  async verifyPasswordResetOTPCode(
    verifyPasswordResetOTPCode: VerifyPasswordResetOTPCodeDto,
  ) {
    const otpVerification = await this.cacheKeyRepository.findOne({
      where: {
        userId: verifyPasswordResetOTPCode.userId,
        service: CacheKeyService.RESET_PASSWORD,
        status: CacheKeyStatus.PENDING,
      },
    });

    if (!otpVerification) {
      throw new BadRequestException('No pending otp verification found');
    }

    // Check if code has expired
    if (new Date() > otpVerification.expiresAt) {
      otpVerification.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(otpVerification);
      throw new BadRequestException('Verification code has expired');
    }

    // Check if max attempts reached
    if (otpVerification.attempts >= otpVerification.maxAttempts) {
      otpVerification.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(otpVerification);
      throw new BadRequestException('Maximum verification attempts exceeded');
    }

    // Increment attempts
    otpVerification.attempts += 1;

    // Verify code
    if (otpVerification.code !== verifyPasswordResetOTPCode.code) {
      await this.cacheKeyRepository.save(otpVerification);
      throw new BadRequestException('Invalid verification code');
    }

    // Mark as active
    otpVerification.status = CacheKeyStatus.VERIFIED;
    await this.cacheKeyRepository.save(otpVerification);

    const payload = {
      sub: verifyPasswordResetOTPCode.userId,
      userId: verifyPasswordResetOTPCode.userId,
      type: CacheKeyService.RESET_PASSWORD,
    };

    const accessToken = this.jwtService.sign(payload);

    return {
      userId: verifyPasswordResetOTPCode.userId,
      accessToken,
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto, request: Request) {
    // Validate and decode access token
    try {
      await this.jwtService.verifyAsync(resetPasswordDto.accessToken);
    } catch {
      throw new UnauthorizedException('Access token verification failed');
    }

    const { userId, type } = this.jwtService.decode(
      resetPasswordDto.accessToken,
    );

    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (type !== CacheKeyService.RESET_PASSWORD) {
      throw new BadRequestException('Invalid access token type');
    }

    // Update password
    user.password = resetPasswordDto.newPassword;
    await this.userRepository.save(user);

    // Log activity
    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.CHANGE_PASSWORD,
      description: 'User password changed successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    await this.userActivityLogRepository.save(userActivityLog);
  }

  async completePasswordSetup(
    setPasswordDto: SetPasswordDto,
    request: Request,
  ) {
    const tokenHash = this.hashToken(setPasswordDto.token);

    const invite = await this.userInviteRepository.findOne({
      where: { token: setPasswordDto.token },
    });

    const cacheKey = await this.cacheKeyRepository.findOne({
      where: {
        code: tokenHash,
        service: CacheKeyService.SET_PASSWORD,
        status: CacheKeyStatus.PENDING,
      },
    });

    if (!cacheKey) {
      if (invite && invite.status === UserInviteStatus.PENDING) {
        invite.status = UserInviteStatus.EXPIRED;
        await this.userInviteRepository.save(invite);
      }
      throw new BadRequestException('Invalid or expired token');
    }

    if (new Date() > cacheKey.expiresAt) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      if (invite) {
        invite.status = UserInviteStatus.EXPIRED;
        await this.userInviteRepository.save(invite);
      }
      throw new BadRequestException('Token has expired');
    }

    const user = await this.userRepository.findOne({
      where: { id: cacheKey.userId },
    });

    if (!user) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      throw new NotFoundException('User not found for token');
    }

    if (invite) {
      if (invite.status !== UserInviteStatus.PENDING) {
        throw new BadRequestException('Invitation is no longer valid');
      }

      if (invite.userId && invite.userId !== user.id) {
        throw new BadRequestException('Invitation token does not match user');
      }

      if (new Date() > invite.expiresAt) {
        invite.status = UserInviteStatus.EXPIRED;
        await this.userInviteRepository.save(invite);
        cacheKey.status = CacheKeyStatus.EXPIRED;
        await this.cacheKeyRepository.save(cacheKey);
        throw new BadRequestException('Invitation has expired');
      }
    }

    user.password = setPasswordDto.newPassword;
    user.lastPasswordChangedAt = new Date();
    user.isActive = true;
    user.status = UserStatus.ACTIVE;
    await this.userRepository.save(user);

    cacheKey.status = CacheKeyStatus.USED;
    await this.cacheKeyRepository.save(cacheKey);

    if (invite) {
      invite.status = UserInviteStatus.ACCEPTED;
      invite.acceptedAt = new Date();
      await this.userInviteRepository.save(invite);
    }

    const existingProvider = await this.userAuthProviderRepository.findOne({
      where: { userId: user.id, provider: 'local' },
    });

    if (!existingProvider) {
      await this.userAuthProviderRepository.save(
        this.userAuthProviderRepository.create({
          userId: user.id,
          provider: 'local',
          providerId: user.id,
        }),
      );
    }

    if (user.roleId) {
      const role = await this.roleRepository.findOne({ where: { id: user.roleId } });
      if (role?.name?.toLowerCase().includes('admin')) {
        await this.ensureAdminProfile(user.id);
      }
    }

    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.CHANGE_PASSWORD,
      description: 'User set password via one-time link',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    return user;
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  private buildAdminUserEntity(
    adminRegisterDto: AdminRegisterDto,
    adminRole?: Role | null,
  ): User {
    const phone = adminRegisterDto.phone?.trim() || `admin-${crypto.randomUUID()}`;
    const normalizedEmail = adminRegisterDto.email.trim().toLowerCase();

    const user = this.userRepository.create({
      email: normalizedEmail,
      phone,
      firstName: adminRegisterDto.firstName,
      lastName: adminRegisterDto.lastName,
      roleId: adminRole?.id,
      authProvider: AuthProviderType.LOCAL,
      isActive: true,
      status: UserStatus.ACTIVE,
      mfaChannel: MfaChannel.EMAIL,
      twoFactorEnabled: false,
    });

    // Use the entity setter so lifecycle hooks hash before persisting
    user.password = adminRegisterDto.password;
    return user;
  }

  private generateVerificationCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }

  private async verifyUserPassword(user: User, plainPassword: string) {
    return verifyPassword(user.passwordHash, plainPassword);
  }
}
