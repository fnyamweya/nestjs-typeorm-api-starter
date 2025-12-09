export const controllerTemplate = `import {
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
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { {{EntityName}}Service } from '../services/{{kebabCaseName}}.service';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { LogActivity } from 'src/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/activity-log/entities/user-activity-log.entity';
import { {{EntityName}} } from '../entities/{{entityFileName}}.entity';
import { Create{{EntityName}}Dto } from '../dto/create-{{kebabCaseName}}.dto';
import { ResponseUtil } from 'src/common/utils/response.util';
import { Filter{{EntityName}}Dto } from '../dto/filter-{{kebabCaseName}}.dto';
import { Update{{EntityName}}Dto } from '../dto/update-{{kebabCaseName}}.dto';

@Controller('api/{{pluralKebabCase}}')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class {{EntityName}}Controller {
  constructor(private readonly {{camelCaseName}}Service: {{EntityName}}Service) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.{{UPPER_SNAKE_CASE}},
    permission: 'create',
  })
  @LogActivity({
    action: ActivityAction.CREATE,
    description: '{{EntityName}} created successfully',
    resourceType: '{{camelCaseName}}',
    getResourceId: (result: {{EntityName}}) => result.id?.toString(),
  })
  async create(@Body() create{{EntityName}}Dto: Create{{EntityName}}Dto) {
    const {{camelCaseName}} = await this.{{camelCaseName}}Service.create(create{{EntityName}}Dto);
    return ResponseUtil.created({{camelCaseName}}, '{{EntityName}} created successfully');
  }

  @Get()
  async findAll(@Query() filters: Filter{{EntityName}}Dto) {
    const result = await this.{{camelCaseName}}Service.findAll(filters);

    if (filters.getAll) {
      return ResponseUtil.success(
        result.data,
        'All {{pluralLowerCase}} retrieved successfully',
      );
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      '{{pluralPascalCase}} retrieved successfully',
    );
  }

  @Get('/:id')
  async findOne(@Param('id') id: string) {
    const {{camelCaseName}} = await this.{{camelCaseName}}Service.findOne(id);
    return ResponseUtil.success(
      {{camelCaseName}},
      \`{{EntityName}} retrieved by ID \${id} successfully\`,
    );
  }

  @Patch('/:id')
  @RequirePermissions({
    module: PermissionModule.{{UPPER_SNAKE_CASE}},
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: '{{EntityName}} updated successfully',
    resourceType: '{{camelCaseName}}',
    getResourceId: (result: {{EntityName}}) => result.id?.toString(),
  })
  async update(
    @Param('id') id: string,
    @Body() update{{EntityName}}Dto: Update{{EntityName}}Dto,
  ) {
    const {{camelCaseName}} = await this.{{camelCaseName}}Service.update(id, update{{EntityName}}Dto);
    return ResponseUtil.updated({{camelCaseName}}, '{{EntityName}} updated successfully');
  }

  @Delete('/:id')
  @RequirePermissions({
    module: PermissionModule.{{UPPER_SNAKE_CASE}},
    permission: 'delete',
  })
  @LogActivity({
    action: ActivityAction.DELETE,
    description: '{{EntityName}} deleted successfully',
    resourceType: '{{camelCaseName}}',
    getResourceId: (params: { id: string }) => params.id,
  })
  async remove(@Param('id') id: string) {
    const result = await this.{{camelCaseName}}Service.remove(id);
    return ResponseUtil.success(result, '{{EntityName}} deleted successfully');
  }
}
`;
