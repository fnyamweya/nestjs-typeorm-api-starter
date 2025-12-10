import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Delete,
  Query,
  UseGuards,
  NotFoundException,
  Patch,
} from '@nestjs/common';
import { RoleService } from '../services/role.service';
import { Role } from '../entities/role.entity';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { PermissionsGuard } from '../guards/permissions.guard';
import { RequirePermissions } from '../decorators/permissions.decorator';
import { PermissionModule } from '../entities/permission.entity';
import { LogActivity } from 'src/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/activity-log/entities/user-activity-log.entity';
import { CreateRoleDto } from '../dto/create-role.dto';
import { UpdateRoleDto } from '../dto/update-role.dto';
import { ApiResponse } from 'src/common/interfaces/api-response.interface';
import { ResponseUtil } from 'src/common/utils/response.util';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiTags,
  ApiUnauthorizedResponse,
  ApiBadRequestResponse,
} from '@nestjs/swagger';

@Controller('roles')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@ApiTags('Roles')
@ApiBearerAuth('access-token')
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Get()
  @RequirePermissions({
    module: PermissionModule.ROLES,
    permission: 'read',
  })
  @ApiOperation({
    summary: 'Retrieve a list of roles with optional pagination',
  })
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
    description: 'Return all roles without pagination',
  })
  @ApiOkResponse({ description: 'Roles retrieved successfully' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to read roles',
  })
  async findAll(
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10,
    @Query('getAll') getAll: boolean = false,
  ): Promise<ApiResponse<Role[]>> {
    const [result, total] = await this.roleService.findAll(page, limit, getAll);

    if (getAll) {
      return ResponseUtil.success(result, 'All roles retrieved successfully');
    }

    return ResponseUtil.paginated(
      result,
      total,
      page,
      limit,
      'Roles retrieved successfully',
    );
  }

  @Get('permissions')
  @RequirePermissions({
    module: PermissionModule.PERMISSIONS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve all available permissions' })
  @ApiOkResponse({ description: 'Permissions retrieved successfully' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to read permissions',
  })
  async findAllPermissions() {
    const permissions = await this.roleService.findAllPermissions();

    return ResponseUtil.success(
      permissions,
      'Permissions retrieved successfully',
    );
  }

  @Get(':id')
  @RequirePermissions({
    module: PermissionModule.ROLES,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve role details by identifier' })
  @ApiParam({ name: 'id', description: 'Role identifier', type: String })
  @ApiOkResponse({ description: 'Role retrieved successfully' })
  @ApiNotFoundResponse({ description: 'Role not found' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to read roles',
  })
  async findOne(@Param('id') id: string): Promise<ApiResponse<Role>> {
    const role = await this.roleService.findOne(id);

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    return ResponseUtil.success(role, 'Role retrieved successfully');
  }

  @Post()
  @RequirePermissions({
    module: PermissionModule.ROLES,
    permission: 'create',
  })
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'Role created successfully',
    resourceType: 'role',
    getResourceId: (result: Role) => result.id?.toString(),
  })
  @ApiOperation({ summary: 'Create a new role' })
  @ApiBody({ type: CreateRoleDto })
  @ApiCreatedResponse({ description: 'Role created successfully' })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to create roles',
  })
  async create(
    @Body() createRoleDto: CreateRoleDto,
  ): Promise<ApiResponse<Role | null>> {
    const role = await this.roleService.create(createRoleDto);
    if (!role) {
      return ResponseUtil.error('Role creation failed');
    }

    return ResponseUtil.created(role, 'Role created successfully');
  }

  @Patch(':id')
  @RequirePermissions({
    module: PermissionModule.ROLES,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Role updated successfully',
    resourceType: 'role',
    getResourceId: (result: Role) => result.id?.toString(),
  })
  @ApiOperation({ summary: 'Update an existing role' })
  @ApiParam({ name: 'id', description: 'Role identifier', type: String })
  @ApiBody({ type: UpdateRoleDto })
  @ApiOkResponse({ description: 'Role updated successfully' })
  @ApiBadRequestResponse({ description: 'Validation failed' })
  @ApiNotFoundResponse({ description: 'Role not found' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to update roles',
  })
  async update(
    @Param('id') id: string,
    @Body() updateRoleDto: UpdateRoleDto,
  ): Promise<ApiResponse<Role>> {
    const role = await this.roleService.update(id, updateRoleDto);

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    return ResponseUtil.updated(role, 'Role updated successfully');
  }

  @Delete(':id')
  @RequirePermissions({
    module: PermissionModule.ROLES,
    permission: 'delete',
  })
  @LogActivity({
    action: ActivityAction.DELETE,
    description: 'Role deleted successfully',
    resourceType: 'role',
    getResourceId: (result: Role) => result.id?.toString(),
  })
  @ApiOperation({ summary: 'Delete a role by identifier' })
  @ApiParam({ name: 'id', description: 'Role identifier', type: String })
  @ApiOkResponse({ description: 'Role deleted successfully' })
  @ApiNotFoundResponse({ description: 'Role not found' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to delete roles',
  })
  async remove(@Param('id') id: string): Promise<ApiResponse<null>> {
    const deleted = await this.roleService.remove(id);

    if (!deleted) {
      throw new NotFoundException('Role not found');
    }

    return ResponseUtil.deleted('Role deleted successfully');
  }
}
