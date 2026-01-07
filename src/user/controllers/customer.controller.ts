import {
  BadRequestException,
  Controller,
  Post,
  Body,
  Patch,
  Get,
  Param,
  Query,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiCreatedResponse,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { CreateCustomerDto } from '../dto/create-customer.dto';
import { InviteCustomerDto } from '../dto/invite-customer.dto';
import { UpdateCustomerDto } from '../dto/update-customer.dto';
import { FilterUserDto } from '../dto/filter-user.dto';
import { UserService } from '../services/user.service';
import { AuthService } from 'src/auth/services/auth.service';
import { InjectRepository } from '@nestjs/typeorm';
import { Role } from 'src/auth/entities/role.entity';
import { ILike, Repository } from 'typeorm';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { AuthenticatedUser } from 'src/auth/interfaces/user.interface';

@Controller('customers')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
@UseGuards(JwtAuthGuard, PermissionsGuard)
@ApiTags('Customers')
@ApiBearerAuth('access-token')
export class CustomerController {
  constructor(
    private readonly userService: UserService,
    private readonly authService: AuthService,
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>,
  ) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'create',
  })
  @ApiOperation({ summary: 'Create a new customer' })
  @ApiCreatedResponse({ description: 'Customer created successfully' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to create customers',
  })
  async create(@Body() payload: CreateCustomerDto) {
    const customer = await this.userService.createCustomer(payload);
    return ResponseUtil.created(customer, 'Customer created successfully');
  }

  @Patch('/:id')
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Update a customer by identifier' })
  @ApiParam({
    name: 'id',
    description: 'Customer user identifier',
    type: String,
  })
  @ApiOkResponse({ description: 'Customer updated successfully' })
  @ApiNotFoundResponse({ description: 'Customer not found' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to update customers',
  })
  async updateCustomer(
    @Param('id') id: string,
    @Body() payload: UpdateCustomerDto,
  ) {
    // Ensure the user is actually a customer
    await this.userService.findCustomerById(id);
    const updated = await this.userService.update(id, payload as any);
    return ResponseUtil.updated(updated, 'Customer updated successfully');
  }

  @Post('invite')
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'create',
  })
  @ApiOperation({
    summary: 'Invite a customer (email + WhatsApp) and let them set password',
  })
  @ApiCreatedResponse({
    description: 'Customer invitation created and notifications sent',
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to invite customers',
  })
  async inviteCustomer(
    @CurrentUser() inviter: AuthenticatedUser,
    @Body() payload: InviteCustomerDto,
  ) {
    const customerRole = await this.roleRepository.findOne({
      where: [{ name: 'customer' } as any, { name: ILike('customer') } as any],
    });

    if (!customerRole) {
      throw new BadRequestException('Customer role is not configured');
    }

    const result = await this.authService.createUserInvite(
      {
        email: payload.email,
        phone: payload.phone,
        firstName: payload.firstName,
        lastName: payload.lastName,
        roleId: customerRole.id,
      },
      inviter,
    );

    return ResponseUtil.created(result, 'Customer invitation sent');
  }

  @Get()
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve a paginated list of customers' })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number (default 1)',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Page size (default 10)',
  })
  @ApiQuery({
    name: 'getAll',
    required: false,
    type: Boolean,
    description: 'Return all customers without pagination when true',
  })
  @ApiQuery({
    name: 'search',
    required: false,
    type: String,
    description: 'Search by name, email, or phone',
  })
  @ApiQuery({
    name: 'isBanned',
    required: false,
    type: Boolean,
    description: 'Filter by banned status',
  })
  @ApiOkResponse({ description: 'Customers retrieved successfully' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to read customers',
  })
  async findAll(@Query() filters: FilterUserDto) {
    const result = await this.userService.findCustomers(filters);

    if (filters.getAll) {
      return ResponseUtil.success(
        result.data,
        'All customers retrieved successfully',
      );
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Customers retrieved successfully',
    );
  }

  @Get('/:id')
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve a customer by identifier' })
  @ApiParam({
    name: 'id',
    description: 'Customer user identifier',
    type: String,
  })
  @ApiOkResponse({ description: 'Customer retrieved successfully' })
  @ApiNotFoundResponse({ description: 'Customer not found' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to read customers',
  })
  async findOne(@Param('id') id: string) {
    const customer = await this.userService.findCustomerById(id);
    return ResponseUtil.success(
      customer,
      `Customer retrieved by ID ${id} successfully`,
    );
  }
}
