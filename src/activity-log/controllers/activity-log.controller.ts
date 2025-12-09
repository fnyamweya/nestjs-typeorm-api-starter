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
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';

@Controller('/api/activity-logs')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ActivityLogController {
  constructor(private readonly activityLogService: ActivityLogService) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.ACTIVITY_LOGS,
    permission: 'create',
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
  async findOne(@Param('id') id: number) {
    const activityLog = await this.activityLogService.findById(id);

    return ResponseUtil.success(
      activityLog,
      'Activity log retrieved successfully',
    );
  }
}
