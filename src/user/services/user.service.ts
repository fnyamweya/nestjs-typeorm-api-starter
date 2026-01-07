import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Brackets, FindManyOptions, ILike, Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { CreateUserDto } from '../dto/create-user.dto';
import { FilterUserDto } from '../dto/filter-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';
import { Role } from 'src/auth/entities/role.entity';
import { hashPassword as hashWithArgon } from 'src/common/utils/password.util';
import { CustomerProfile } from '../entities/customer-profile.entity';
import { CreateCustomerDto } from '../dto/create-customer.dto';
import { AuthProviderType, MfaChannel, UserStatus } from '../enums';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRepository(CustomerProfile)
    private customerProfileRepository: Repository<CustomerProfile>,
    private s3ClientUtils: S3ClientUtils,
  ) {}

  async createCustomer(payload: CreateCustomerDto): Promise<User> {
    const existingByPhone = await this.userRepository.findOne({
      where: { phone: payload.phone },
    });
    if (existingByPhone) {
      throw new ConflictException('Phone number is already registered');
    }

    if (payload.email) {
      const existingByEmail = await this.userRepository.findOne({
        where: { email: payload.email },
      });
      if (existingByEmail) {
        throw new ConflictException('Email is already registered');
      }
    }

    const customerRole = await this.roleRepository.findOne({
      where: [{ name: 'customer' } as any, { name: ILike('customer') } as any],
    });

    if (!customerRole) {
      throw new NotFoundException('Customer role is not configured');
    }

    const user = this.userRepository.create({
      email: payload.email,
      phone: payload.phone,
      firstName: payload.firstName,
      lastName: payload.lastName,
      roleId: customerRole.id,
      authProvider: AuthProviderType.LOCAL,
      isActive: true,
      status: UserStatus.ACTIVE,
      mfaChannel: MfaChannel.EMAIL,
      twoFactorEnabled: false,
    });
    user.passwordHash = payload.password;

    const savedUser = await this.userRepository.save(user);

    const profileExists = await this.customerProfileRepository.findOne({
      where: { userId: savedUser.id } as any,
    });
    if (!profileExists) {
      await this.customerProfileRepository.save(
        this.customerProfileRepository.create({ userId: savedUser.id }),
      );
    }

    return this.findCustomerById(savedUser.id);
  }

  async create(
    createUserDto: CreateUserDto,
    profileImage?: Express.Multer.File,
  ) {
    // Check if user with same email already exists
    const existingUser = await this.userRepository.findOne({
      where: { email: createUserDto.email },
    });

    if (existingUser) {
      throw new ConflictException(
        `User with email '${createUserDto.email}' already exists`,
      );
    }

    // Check if roleId is provided and exists
    if (createUserDto.roleId) {
      const role = await this.roleRepository.findOne({
        where: { id: createUserDto.roleId },
      });
      if (!role) {
        throw new NotFoundException(
          `Role with ID '${createUserDto.roleId}' not found`,
        );
      }
    }

    let profileImageKey = '';
    if (profileImage) {
      const { key } = await this.s3ClientUtils.uploadFile({
        key: profileImage.originalname,
        body: profileImage.buffer,
        contentType: profileImage.mimetype,
        path: 'profile-images',
      });

      profileImageKey = key || '';
    }

    const user = this.userRepository.create({
      ...createUserDto,
      profileImageUrl: profileImageKey,
    });
    return await this.userRepository.save(user);
  }

  async findAll(filter: FilterUserDto) {
    const { getAll, limit, page } = filter;
    const skip = (page - 1) * limit;
    const findOptions: FindManyOptions<User> = {
      order: { createdAt: 'DESC' },
      relations: ['role'],
    };

    if (!getAll) {
      findOptions.skip = skip;
      findOptions.take = limit;
    }

    if (filter.search) {
      findOptions.where = [
        { firstName: ILike(`%${filter.search}%`) },
        { lastName: ILike(`%${filter.search}%`) },
        { email: ILike(`%${filter.search}%`) },
        { phone: ILike(`%${filter.search}%`) },
      ];
    }

    if (filter.isBanned !== undefined) {
      findOptions.where = {
        ...findOptions.where,
        isBanned: filter.isBanned,
      };
    }

    const [data, total] = await this.userRepository.findAndCount(findOptions);

    // Add presigned URL to each user
    const usersWithPresignedUrl = await Promise.all(
      data.map(async (user) => {
        user.profileImageUrl =
          (await this.s3ClientUtils.generatePresignedUrl(
            user.profileImageUrl || '',
          )) || '';
        return user;
      }),
    );

    return {
      data: usersWithPresignedUrl,
      total,
      page,
      limit,
    };
  }

  async findCustomers(filter: FilterUserDto) {
    const { getAll, limit, page } = filter;
    const skip = (page - 1) * limit;

    const qb = this.userRepository
      .createQueryBuilder('user')
      .innerJoinAndSelect('user.customerProfile', 'customerProfile')
      .leftJoinAndSelect('user.role', 'role')
      .orderBy('user.createdAt', 'DESC');

    if (filter.search) {
      const search = `%${filter.search}%`;
      qb.andWhere(
        new Brackets((where) => {
          where
            .where('user.firstName ILIKE :search', { search })
            .orWhere('user.lastName ILIKE :search', { search })
            .orWhere('user.email ILIKE :search', { search })
            .orWhere('user.phone ILIKE :search', { search });
        }),
      );
    }

    if (filter.isBanned !== undefined) {
      qb.andWhere('user.isBanned = :isBanned', { isBanned: filter.isBanned });
    }

    if (!getAll) {
      qb.skip(skip).take(limit);
    }

    const [data, total] = await qb.getManyAndCount();

    const usersWithPresignedUrl = await Promise.all(
      data.map(async (user) => {
        user.profileImageUrl =
          (await this.s3ClientUtils.generatePresignedUrl(
            user.profileImageUrl || '',
          )) || '';
        return user;
      }),
    );

    return {
      data: usersWithPresignedUrl,
      total,
      page,
      limit,
    };
  }

  async findCustomerById(id: string) {
    const user = await this.userRepository
      .createQueryBuilder('user')
      .innerJoinAndSelect('user.customerProfile', 'customerProfile')
      .leftJoinAndSelect('user.role', 'role')
      .where('user.id = :id', { id })
      .getOne();

    if (!user) {
      throw new NotFoundException(`Customer with ID '${id}' not found`);
    }

    user.profileImageUrl =
      (await this.s3ClientUtils.generatePresignedUrl(
        user.profileImageUrl || '',
      )) || '';

    return user;
  }

  async findOne(id: string) {
    const user = await this.userRepository.findOne({
      where: { id },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });
    if (!user) {
      throw new NotFoundException(`User with ID '${id}' not found`);
    }

    // Add presigned URL to user
    user.profileImageUrl =
      (await this.s3ClientUtils.generatePresignedUrl(
        user.profileImageUrl || '',
      )) || '';

    return user;
  }

  async update(
    id: string,
    updateUserDto: UpdateUserDto,
    profileImage?: Express.Multer.File,
  ) {
    // Check if user exists
    const existingUser = await this.userRepository.findOne({ where: { id } });

    if (!existingUser) {
      throw new NotFoundException(`User with ID '${id}' not found`);
    }

    // If email is being updated, check for duplicates
    if (updateUserDto.email && updateUserDto.email !== existingUser.email) {
      const duplicateUser = await this.userRepository.findOne({
        where: { email: updateUserDto.email },
      });
      if (duplicateUser) {
        throw new ConflictException(
          `User with email '${updateUserDto.email}' already exists`,
        );
      }
    }

    // Check if roleId is provided and exists
    if (updateUserDto.roleId) {
      const role = await this.roleRepository.findOne({
        where: { id: updateUserDto.roleId },
      });
      if (!role) {
        throw new NotFoundException(
          `Role with ID '${updateUserDto.roleId}' not found`,
        );
      }
    }

    let profileImageKey = existingUser.profileImageUrl || '';
    if (profileImage) {
      // Delete previous profile image from S3
      if (
        existingUser.profileImageUrl &&
        (await this.s3ClientUtils.objectExists(existingUser.profileImageUrl))
      ) {
        await this.s3ClientUtils.deleteObject(existingUser.profileImageUrl);
      }

      // Upload new profile image to S3
      const { key: profileImageUploadedKey } =
        await this.s3ClientUtils.uploadFile({
          key: `${profileImage.originalname}-${new Date().getTime()}`,
          body: profileImage.buffer,
          contentType: profileImage.mimetype,
          path: 'profile-images',
        });

      profileImageKey = profileImageUploadedKey || '';
    }

    // Update the user
    const updatedUser = await this.userRepository.preload({
      id,
      ...updateUserDto,
      profileImageUrl: profileImageKey,
    });

    if (!updatedUser) {
      throw new NotFoundException(`User with ID '${id}' not found`);
    }

    if (updateUserDto.password) {
      updatedUser.password = await hashWithArgon(updateUserDto.password);
    }

    return await this.userRepository.save(updatedUser);
  }

  async remove(id: string) {
    const user = await this.findOne(id);
    // Remove profile image if it exists
    if (
      user.profileImageUrl &&
      (await this.s3ClientUtils.objectExists(user.profileImageUrl))
    ) {
      await this.s3ClientUtils.deleteObject(user.profileImageUrl);
    }

    await this.userRepository.remove(user);
    return {
      message: `User with ID '${id}' has been successfully deleted`,
    };
  }
}
