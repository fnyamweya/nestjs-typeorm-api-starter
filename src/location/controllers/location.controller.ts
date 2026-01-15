import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { ResponseUtil } from 'src/common/utils/response.util';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { CreateLocationDto } from '../dto/create-location.dto';
import { UpdateLocationDto } from '../dto/update-location.dto';
import { ListLocationsDto } from '../dto/list-locations.dto';
import { LocationService } from '../services/location.service';

@Controller('locations')
@ApiTags('Locations')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
export class LocationController {
  constructor(private readonly locationService: LocationService) {}

  @Post()
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({
    module: PermissionModule.LOCATIONS,
    permission: 'create',
  })
  @ApiOperation({
    summary: 'Create a location node',
    description:
      'Creates a location. The allowed `type` values and parent→child rules are country-configurable via `GET/PUT /api/v1/addresses/field-config?countryCode=...` (`schema.locationChain`). Use countryId to select the country.',
  })
  @ApiCreatedResponse({ description: 'Location created' })
  async create(@Body() payload: CreateLocationDto) {
    const row = await this.locationService.create(payload);
    return ResponseUtil.created(row, 'Location created');
  }

  @Get('allowed-children')
  @ApiOperation({
    summary: 'Get allowed child types',
    description:
      'Returns which child `type` values are allowed under a given parent, based on the configured country locationChain. Requires countryId.',
  })
  @ApiQuery({
    name: 'countryId',
    required: true,
    description: 'Country UUID (from country_config)',
    example: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
  })
  @ApiQuery({
    name: 'parentId',
    required: false,
    description:
      'Parent location UUID (preferred over parentType when available)',
    example: '2d1a2b1f-1c9a-4d7b-b44a-9b2a8123c812',
  })
  @ApiQuery({
    name: 'parentType',
    required: false,
    description:
      'Parent type (case-insensitive). Example: country, county, district',
    example: 'country',
  })
  @ApiOkResponse({ description: 'Allowed child types retrieved' })
  async allowedChildren(
    @Query('countryId') countryId: string,
    @Query('parentId') parentId?: string,
    @Query('parentType') parentType?: string,
  ) {
    const res = await this.locationService.getAllowedChildTypes({
      countryId,
      parentId,
      parentType: parentType ? String(parentType).toLowerCase() : undefined,
    });
    return ResponseUtil.success(res, 'Allowed child types retrieved');
  }

  @Patch(':id')
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({
    module: PermissionModule.LOCATIONS,
    permission: 'update',
  })
  @ApiOperation({
    summary: 'Update a location',
    description:
      'Updates a location. If you change `parentId` or `type`, the service enforces country-configured parent→child rules from `addresses/field-config.locationChain`.',
  })
  @ApiParam({ name: 'id', description: 'Location UUID' })
  @ApiOkResponse({ description: 'Location updated' })
  async update(@Param('id') id: string, @Body() payload: UpdateLocationDto) {
    const row = await this.locationService.update(id, payload);
    return ResponseUtil.success(row, 'Location updated');
  }

  @Delete(':id')
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({
    module: PermissionModule.LOCATIONS,
    permission: 'delete',
  })
  @ApiOperation({
    summary: 'Delete a location',
    description:
      'Deletes a location. Use force=true to delete even if it has children (recursive behavior depends on DB constraints).',
  })
  @ApiParam({ name: 'id', description: 'Location UUID' })
  @ApiQuery({
    name: 'force',
    required: false,
    description: 'When true, allows deleting a location with children',
    example: 'true',
  })
  @ApiOkResponse({ description: 'Location deleted' })
  async delete(@Param('id') id: string, @Query('force') force?: string) {
    const res = await this.locationService.delete(id, {
      force: force === 'true',
    });
    return ResponseUtil.success(res, 'Location deleted');
  }

  @Get()
  @ApiOperation({
    summary: 'List locations',
    description:
      'Filters locations by country/type/parent/search. `type` is dynamic per-country (from `addresses/field-config.locationChain`). For compatibility, `locationType` is accepted as an alias for `type`.',
  })
  @ApiQuery({
    name: 'countryId',
    required: false,
    description: 'Country UUID (from country_config)',
    example: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
  })
  @ApiQuery({
    name: 'type',
    required: false,
    description: 'Location type (case-insensitive)',
    example: 'country',
  })
  @ApiQuery({
    name: 'locationType',
    required: false,
    description:
      'Alias for type (deprecated). Accepts COUNTRY, county, district, etc.',
    example: 'COUNTRY',
  })
  @ApiQuery({
    name: 'parentId',
    required: false,
    description: 'Parent location UUID (omit for roots)',
    example: '2d1a2b1f-1c9a-4d7b-b44a-9b2a8123c812',
  })
  @ApiQuery({
    name: 'q',
    required: false,
    description: 'Search by name (case-insensitive)',
    example: 'nai',
  })
  @ApiOkResponse({ description: 'Locations retrieved' })
  async list(@Query() query: ListLocationsDto) {
    const rows = await this.locationService.list(query);
    return ResponseUtil.success(rows, 'Locations retrieved');
  }

  @Get('tree/:countryId')
  @ApiOperation({ summary: 'Get location tree for a country' })
  @ApiParam({
    name: 'countryId',
    description: 'Country UUID (from country_config)',
    example: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
  })
  @ApiOkResponse({ description: 'Location tree retrieved' })
  async tree(@Param('countryId') countryId: string) {
    const rows = await this.locationService.getTreeByCountryId(countryId);
    return ResponseUtil.success(rows, 'Location tree retrieved');
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a location by id' })
  @ApiParam({ name: 'id', description: 'Location UUID' })
  @ApiOkResponse({ description: 'Location retrieved' })
  async get(@Param('id') id: string) {
    const row = await this.locationService.getById(id);
    return ResponseUtil.success(row, 'Location retrieved');
  }
}
