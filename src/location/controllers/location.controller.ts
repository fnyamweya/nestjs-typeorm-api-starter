import { Body, Controller, Delete, Get, Param, Patch, Post, Query, UseGuards, UsePipes, ValidationPipe } from '@nestjs/common';
import { ApiBearerAuth, ApiCreatedResponse, ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { ResponseUtil } from 'src/common/utils/response.util';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { CreateLocationDto } from '../dto/create-location.dto';
import { UpdateLocationDto } from '../dto/update-location.dto';
import { ListLocationsDto } from '../dto/list-locations.dto';
import { LocationService } from '../services/location.service';
import { LocationType } from '../entities/location.entity';

@Controller('locations')
@ApiTags('Locations')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))
export class LocationController {
  constructor(private readonly locationService: LocationService) {}

  @Post()
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.LOCATIONS, permission: 'create' })
  @ApiCreatedResponse({ description: 'Location created' })
  async create(@Body() payload: CreateLocationDto) {
    const row = await this.locationService.create(payload);
    return ResponseUtil.created(row, 'Location created');
  }

  @Get('allowed-children')
  @ApiOkResponse({ description: 'Allowed child types retrieved' })
  async allowedChildren(
    @Query('countryCode') countryCode: string,
    @Query('parentId') parentId?: string,
    @Query('parentType') parentType?: LocationType,
  ) {
    const res = await this.locationService.getAllowedChildTypes({
      countryCode: (countryCode || 'KE').toUpperCase(),
      parentId,
      parentType,
    });
    return ResponseUtil.success(res, 'Allowed child types retrieved');
  }

  @Patch(':id')
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.LOCATIONS, permission: 'update' })
  @ApiOkResponse({ description: 'Location updated' })
  async update(@Param('id') id: string, @Body() payload: UpdateLocationDto) {
    const row = await this.locationService.update(id, payload);
    return ResponseUtil.success(row, 'Location updated');
  }

  @Delete(':id')
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.LOCATIONS, permission: 'delete' })
  @ApiOkResponse({ description: 'Location deleted' })
  async delete(@Param('id') id: string, @Query('force') force?: string) {
    const res = await this.locationService.delete(id, { force: force === 'true' });
    return ResponseUtil.success(res, 'Location deleted');
  }

  @Get()
  @ApiOkResponse({ description: 'Locations retrieved' })
  async list(@Query() query: ListLocationsDto) {
    const rows = await this.locationService.list(query);
    return ResponseUtil.success(rows, 'Locations retrieved');
  }

  @Get('tree/:countryCode')
  @ApiOkResponse({ description: 'Location tree retrieved' })
  async tree(@Param('countryCode') countryCode: string) {
    const rows = await this.locationService.getTreeByCountryCode(countryCode.toUpperCase());
    return ResponseUtil.success(rows, 'Location tree retrieved');
  }

  @Get(':id')
  @ApiOkResponse({ description: 'Location retrieved' })
  async get(@Param('id') id: string) {
    const row = await this.locationService.getById(id);
    return ResponseUtil.success(row, 'Location retrieved');
  }
}
