import {
  Controller,
  ValidationPipe,
  UsePipes,
  UseGuards,
  Post,
  Body,
  Get,
  Query,
  Param,
  Patch,
  Delete,
  UseInterceptors,
  UploadedFiles,
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { UserService } from '../services/user.service';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { LogActivity } from 'src/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/activity-log/entities/user-activity-log.entity';
import { User } from '../entities/user.entity';
import { CreateUserDto } from '../dto/create-user.dto';
import { ResponseUtil } from 'src/common/utils/response.util';
import { FilterUserDto } from '../dto/filter-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { AnyFilesInterceptor } from '@nestjs/platform-express';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiTags,
  ApiOkResponse,
  ApiCreatedResponse,
  ApiNotFoundResponse,
  ApiBadRequestResponse,
  ApiForbiddenResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

@Controller('users')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
@UseGuards(JwtAuthGuard, PermissionsGuard)
@ApiTags('Users')
@ApiBearerAuth('access-token')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  @UseInterceptors(AnyFilesInterceptor())
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'create',
  })
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'User created successfully',
    resourceType: 'user',
    getResourceId: (result: User) => result.id?.toString(),
  })
  @ApiOperation({ summary: 'Create a new user account' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'Payload for creating a user including optional profile image',
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'jane.doe@example.com' },
        fullName: { type: 'string', example: 'Jane Doe' },
        password: { type: 'string', example: 'Str0ngP@ssw0rd' },
        phone: { type: 'string', example: '+14155551234' },
        roleId: {
          type: 'string',
          format: 'uuid',
          example: '2d931510-d99f-494a-8c67-87feb05e1594',
        },
        profileImage: { type: 'string', format: 'binary' },
      },
      required: ['email', 'fullName', 'password'],
    },
  })
  @ApiCreatedResponse({ description: 'User created successfully' })
  @ApiBadRequestResponse({
    description: 'Validation failed or invalid file upload',
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to create users',
  })
  async create(
    @Body() createUserDto: CreateUserDto,
    @UploadedFiles()
    files: Express.Multer.File[],
  ) {
    const profileImage = files.find(
      (file) => file.fieldname === 'profileImage',
    );

    const user = await this.userService.create(createUserDto, profileImage);
    return ResponseUtil.created(user, 'User created successfully');
  }

  @Get()
  @ApiOperation({ summary: 'Retrieve a paginated list of users' })
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
    description: 'Return all users without pagination when true',
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
  @ApiOkResponse({ description: 'Users retrieved successfully' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to read users',
  })
  async findAll(@Query() filters: FilterUserDto) {
    const result = await this.userService.findAll(filters);

    if (filters.getAll) {
      return ResponseUtil.success(
        result.data,
        'All users retrieved successfully',
      );
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Users retrieved successfully',
    );
  }

  @Get('/:id')
  @ApiOperation({ summary: 'Retrieve a user by identifier' })
  @ApiParam({ name: 'id', description: 'User identifier', type: String })
  @ApiOkResponse({ description: 'User retrieved successfully' })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to read users',
  })
  async findOne(@Param('id') id: string) {
    const user = await this.userService.findOne(id);
    return ResponseUtil.success(
      user,
      `User retrieved by ID ${id} successfully`,
    );
  }

  @Patch('/:id')
  @UseInterceptors(AnyFilesInterceptor())
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'User updated successfully',
    resourceType: 'user',
    getResourceId: (result: User) => result.id?.toString(),
  })
  @ApiOperation({ summary: 'Update an existing user' })
  @ApiParam({ name: 'id', description: 'User identifier', type: String })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'Payload for updating a user including optional profile image',
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'jane.doe@example.com' },
        fullName: { type: 'string', example: 'Jane Doe' },
        password: { type: 'string', example: 'Str0ngP@ssw0rd' },
        phone: { type: 'string', example: '+14155551234' },
        roleId: {
          type: 'string',
          format: 'uuid',
          example: '2d931510-d99f-494a-8c67-87feb05e1594',
        },
        profileImage: { type: 'string', format: 'binary' },
      },
    },
  })
  @ApiOkResponse({ description: 'User updated successfully' })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiBadRequestResponse({
    description: 'Validation failed or invalid file upload',
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to update users',
  })
  async update(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
    @UploadedFiles()
    files: Express.Multer.File[],
  ) {
    const profileImage = files.find(
      (file) => file.fieldname === 'profileImage',
    );

    const user = await this.userService.update(id, updateUserDto, profileImage);
    return ResponseUtil.updated(user, 'User updated successfully');
  }

  @Delete('/:id')
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'delete',
  })
  @LogActivity({
    action: ActivityAction.DELETE,
    description: 'User deleted successfully',
    resourceType: 'user',
    getResourceId: (params: { id: string }) => params.id,
  })
  @ApiOperation({ summary: 'Delete a user by identifier' })
  @ApiParam({ name: 'id', description: 'User identifier', type: String })
  @ApiOkResponse({ description: 'User deleted successfully' })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to delete users',
  })
  async remove(@Param('id') id: string) {
    const result = await this.userService.remove(id);
    return ResponseUtil.success(result, 'User deleted successfully');
  }
}
