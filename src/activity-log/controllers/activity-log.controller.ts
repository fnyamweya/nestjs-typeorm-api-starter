import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  Param,
  UseGuards,
} from '@nestjs/common';
import { ActivityLogService } from '../services/activity-log.service';
import { CreateActivityLogDto } from '../dto/create-activity-log.dto';
import { FilterActivityLogDto } from '../dto/filter-activity-log.dto';
import { ActivityAction } from '../entities/user-activity-log.entity';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiTags,
  ApiUnauthorizedResponse,
  ApiForbiddenResponse,
  ApiCreatedResponse,
} from '@nestjs/swagger';

@Controller('/api/activity-logs')
@UseGuards(JwtAuthGuard, RolesGuard, PermissionsGuard)
@ApiTags('Activity Logs')
@ApiBearerAuth('access-token')
export class ActivityLogController {
  constructor(private readonly activityLogService: ActivityLogService) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.ACTIVITY_LOGS,
    permission: 'create',
  })
  @ApiOperation({ summary: 'Create an activity log entry manually' })
  @ApiBody({ type: CreateActivityLogDto })
  @ApiCreatedResponse({ description: 'Activity log created successfully' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to create activity logs',
  })
  async create(@Body() createActivityLogDto: CreateActivityLogDto) {
    const activityLog =
      await this.activityLogService.create(createActivityLogDto);

    return ResponseUtil.success(
      activityLog,
      'Activity log created successfully',
    );
  }

  @Get()
  @RequirePermissions({
    module: PermissionModule.ACTIVITY_LOGS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve a paginated list of activity logs' })
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
    description: 'Return all logs without pagination',
  })
  @ApiQuery({
    name: 'userId',
    required: false,
    type: String,
    description: 'Filter by user identifier',
  })
  @ApiQuery({
    name: 'action',
    required: false,
    enum: ActivityAction,
    description: 'Filter by activity action type',
  })
  @ApiQuery({
    name: 'isActivityLog',
    required: false,
    type: Boolean,
    description: 'Restrict to activity log events',
  })
  @ApiQuery({
    name: 'resourceType',
    required: false,
    type: String,
    description: 'Filter by resource type',
  })
  @ApiQuery({
    name: 'resourceId',
    required: false,
    type: String,
    description: 'Filter by resource identifier',
  })
  @ApiQuery({
    name: 'ipAddress',
    required: false,
    type: String,
    description: 'Filter by IP address',
  })
  @ApiQuery({
    name: 'startDate',
    required: false,
    type: String,
    description: 'ISO date string for start date',
  })
  @ApiQuery({
    name: 'endDate',
    required: false,
    type: String,
    description: 'ISO date string for end date',
  })
  @ApiOkResponse({ description: 'Activity logs retrieved successfully' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to read activity logs',
  })
  async findAll(@Query() filterDto: FilterActivityLogDto) {
    const result = await this.activityLogService.findAll(filterDto);

    if (filterDto.getAll) {
      return ResponseUtil.success(
        result.data,
        'All activity logs retrieved successfully',
      );
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      filterDto.page || 1,
      filterDto.limit || 10,
      'Activity logs retrieved successfully',
    );
  }

  @Get(':id')
  @RequirePermissions({
    module: PermissionModule.ACTIVITY_LOGS,
    permission: 'read',
  })
  @ApiOperation({ summary: 'Retrieve a single activity log' })
  @ApiParam({
    name: 'id',
    description: 'Activity log identifier',
    type: Number,
  })
  @ApiOkResponse({ description: 'Activity log retrieved successfully' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to read activity logs',
  })
  async findOne(@Param('id') id: number) {
    const activityLog = await this.activityLogService.findById(id);

    return ResponseUtil.success(
      activityLog,
      'Activity log retrieved successfully',
    );
  }
}
