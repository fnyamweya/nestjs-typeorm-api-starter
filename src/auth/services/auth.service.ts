import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, ILike } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { ConfigService } from '@nestjs/config';
import { User } from 'src/user/entities/user.entity';
import { RefreshToken } from '../entities/refresh-token.entity';
import { JwtPayload } from '../interfaces/user.interface';
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
import { CustomerLoginDto } from '../dto/customer-login.dto';
import { AdminLoginDto } from '../dto/admin-login.dto';
import { CustomerRegisterDto } from '../dto/customer-register.dto';
import { CustomerProfile } from 'src/user/entities/customer-profile.entity';
import { Role } from '../entities/role.entity';
import { AdminRegisterDto } from '../dto/admin-register.dto';
import { AdminProfile } from 'src/user/entities/admin-profile.entity';

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
    private jwtService: JwtService,
    private configService: ConfigService,
    private twoFactorService: TwoFactorService,
    private s3ClientUtils: S3ClientUtils,
    private emailServiceUtils: EmailServiceUtils,
  ) {}

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

    if (!(await bcrypt.compare(plainPassword, user.passwordHash || ''))) {
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

    const fullName =
      customerRegisterDto.fullName ||
      [customerRegisterDto.firstName, customerRegisterDto.lastName]
        .filter(Boolean)
        .join(' ')
        .trim();

    const user = this.userRepository.create({
      email: customerRegisterDto.email,
      phone: customerRegisterDto.phone,
      password: customerRegisterDto.password,
      firstName: customerRegisterDto.firstName,
      lastName: customerRegisterDto.lastName,
      fullName: fullName || customerRegisterDto.phone,
      roleType: 'customer',
      roleId: customerRole?.id,
      authProvider: 'local',
      isActive: true,
      mfaChannel: 'email',
    });

    const savedUser = await this.userRepository.save(user);

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

    const fullName =
      adminRegisterDto.fullName ||
      [adminRegisterDto.firstName, adminRegisterDto.lastName]
        .filter(Boolean)
        .join(' ')
        .trim();

    const user = this.userRepository.create({
      email: adminRegisterDto.email,
      phone: adminRegisterDto.phone,
      password: adminRegisterDto.password,
      firstName: adminRegisterDto.firstName,
      lastName: adminRegisterDto.lastName,
      fullName: fullName || adminRegisterDto.email,
      roleType: 'admin',
      roleId: adminRole?.id,
      authProvider: 'local',
      isActive: true,
      mfaChannel: 'email',
    });

    const savedUser = await this.userRepository.save(user);

    const profile = this.adminProfileRepository.create({
      userId: savedUser.id,
    });
    await this.adminProfileRepository.save(profile);

    return this.completeLogin(savedUser, request);
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

    const isCustomer =
      user?.roleType === 'customer' ||
      user?.role?.name?.toLowerCase() === 'customer';

    if (!user || !isCustomer) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.isBanned || user.isActive === false) {
      throw new UnauthorizedException('Account is disabled');
    }

    const isPasswordValid = await bcrypt.compare(
      customerLoginDto.password,
      user.passwordHash || '',
    );

    if (!isPasswordValid) {
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

    const isAdmin =
      user?.roleType === 'admin' || user?.role?.name?.toLowerCase() === 'admin';

    if (!user || !isAdmin) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.isBanned || user.isActive === false) {
      throw new UnauthorizedException('Account is disabled');
    }

    const isPasswordValid = await bcrypt.compare(
      adminLoginDto.password,
      user.passwordHash || '',
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
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

    return this.completeLogin(user, request);
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
      accessTokenExpiresAt: this.configService.get<string>(
        'JWT_EXPIRATION',
        '15m',
      ),
      refreshTokenExpiresAt: this.configService.get<string>(
        'JWT_REFRESH_EXPIRATION',
        '7d',
      ),
      user: {
        id: user.id,
      },
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
    const isCurrentPasswordValid = await bcrypt.compare(
      changePasswordDto.currentPassword,
      user.passwordHash || '',
    );

    if (!isCurrentPasswordValid) {
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
    await this.emailServiceUtils.sendForgotPasswordResetCode({
      code,
      email: user.email,
      userName: user.fullName,
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

  private generateVerificationCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }
}
