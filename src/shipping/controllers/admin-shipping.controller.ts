import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ShippingAdminService } from '../services/shipping-admin.service';
import { CreateShippingZoneDto } from '../dto/create-shipping-zone.dto';
import { CreateShippingZoneLocationDto } from '../dto/create-shipping-zone-location.dto';
import { AttachShippingZoneLocationDto } from '../dto/attach-shipping-zone-location.dto';
import { CreateShippingMethodDto } from '../dto/create-shipping-method.dto';
import { CreateShippingRateDto } from '../dto/create-shipping-rate.dto';
import { CreateZoneShippingMethodDto } from '../dto/create-zone-shipping-method.dto';
import { CreateMethodShippingRateDto } from '../dto/create-method-shipping-rate.dto';
import { ApiBearerAuth, ApiBody, ApiCreatedResponse, ApiTags, ApiOkResponse, ApiOperation } from '@nestjs/swagger';
import { ResponseUtil } from 'src/common/utils/response.util';

@Controller('shipping')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@ApiTags('Shipping')
@ApiBearerAuth('access-token')
export class AdminShippingController {
  constructor(private readonly adminService: ShippingAdminService) {}

  // Zones
  @Post('zones')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'create' })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a shipping zone' })
  @ApiBody({ type: CreateShippingZoneDto })
  @ApiCreatedResponse({ description: 'Shipping zone created' })
  async createZone(@Body() payload: CreateShippingZoneDto) {
    const z = await this.adminService.createZone(payload);
    return ResponseUtil.created(z, 'Shipping zone created');
  }

  @Get('zones')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'List shipping zones' })
  @ApiOkResponse({ description: 'List of shipping zones' })
  async listZones() {
    const z = await this.adminService.listZones();
    return ResponseUtil.success(z, 'Shipping zones retrieved');
  }

  @Get('zones/:id')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'Get shipping zone' })
  @ApiOkResponse({ description: 'Shipping zone details' })
  async getZone(@Param('id') id: string) {
    const z = await this.adminService.getZone(id);
    return ResponseUtil.success(z, 'Shipping zone retrieved');
  }

  @Put('zones/:id')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'update' })
  @ApiOperation({ summary: 'Update shipping zone' })
  @ApiOkResponse({ description: 'Shipping zone updated' })
  async updateZone(@Param('id') id: string, @Body() payload: Partial<CreateShippingZoneDto>) {
    const z = await this.adminService.updateZone(id, payload);
    return ResponseUtil.success(z, 'Shipping zone updated');
  }

  @Delete('zones/:id')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'delete' })
  @ApiOperation({ summary: 'Delete shipping zone' })
  @ApiOkResponse({ description: 'Shipping zone deleted' })
  async deleteZone(@Param('id') id: string) {
    const ok = await this.adminService.deleteZone(id);
    return ResponseUtil.success({ deleted: ok }, 'Shipping zone deleted');
  }

  @Get('zones/:id/locations')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'List locations attached to a shipping zone' })
  @ApiOkResponse({ description: 'List of shipping zone locations for the zone' })
  async listZoneLocationsForZone(@Param('id') id: string) {
    const rows = await this.adminService.listZoneLocations(id);
    return ResponseUtil.success(rows, 'Shipping zone locations retrieved');
  }

  @Post('zones/:id/locations')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'create' })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Attach a location to a shipping zone (nested route)' })
  @ApiBody({ type: AttachShippingZoneLocationDto })
  @ApiCreatedResponse({ description: 'Shipping zone location created' })
  async createZoneLocationForZone(@Param('id') id: string, @Body() payload: AttachShippingZoneLocationDto) {
    const row = await this.adminService.createZoneLocation({
      zoneId: id,
      locationId: payload.locationId,
      type: payload.type,
    });
    return ResponseUtil.created(row, 'Shipping zone location created');
  }

  @Get('zones/:id/methods')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'List shipping methods for a zone (nested route)' })
  @ApiOkResponse({ description: 'List of shipping methods for the zone' })
  async listMethodsForZone(@Param('id') id: string) {
    const rows = await this.adminService.listMethods(id);
    return ResponseUtil.success(rows, 'Shipping methods retrieved');
  }

  @Post('zones/:id/methods')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'create' })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a shipping method for a zone (nested route)' })
  @ApiBody({ type: CreateZoneShippingMethodDto })
  @ApiCreatedResponse({ description: 'Shipping method created' })
  async createMethodForZone(@Param('id') id: string, @Body() payload: CreateZoneShippingMethodDto) {
    const r = await this.adminService.createMethod({
      zoneId: id,
      code: payload.code,
      displayName: payload.displayName,
      provider: payload.provider,
      isActive: payload.isActive,
    } as CreateShippingMethodDto);
    return ResponseUtil.created(r, 'Shipping method created');
  }

  // Zone locations (locationId-based)
  @Post('zone-locations')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'create' })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Attach a location to a shipping zone' })
  @ApiBody({ type: CreateShippingZoneLocationDto })
  @ApiCreatedResponse({ description: 'Shipping zone location created' })
  async createZoneLocation(@Body() payload: CreateShippingZoneLocationDto) {
    const row = await this.adminService.createZoneLocation(payload);
    return ResponseUtil.created(row, 'Shipping zone location created');
  }

  @Get('zone-locations')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'List shipping zone location mappings' })
  @ApiOkResponse({ description: 'List of shipping zone locations' })
  async listZoneLocations() {
    const rows = await this.adminService.listZoneLocations();
    return ResponseUtil.success(rows, 'Shipping zone locations retrieved');
  }

  @Delete('zone-locations/:id')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'delete' })
  @ApiOperation({ summary: 'Delete shipping zone location mapping' })
  @ApiOkResponse({ description: 'Shipping zone location deleted' })
  async deleteZoneLocation(@Param('id') id: string) {
    const ok = await this.adminService.deleteZoneLocation(id);
    return ResponseUtil.success({ deleted: ok }, 'Shipping zone location deleted');
  }

  // Methods
  @Post('methods')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'create' })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a shipping method' })
  @ApiBody({ type: CreateShippingMethodDto })
  @ApiCreatedResponse({ description: 'Shipping method created' })
  async createMethod(@Body() payload: CreateShippingMethodDto) {
    const r = await this.adminService.createMethod(payload);
    return ResponseUtil.created(r, 'Shipping method created');
  }

  @Get('methods')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'List shipping methods' })
  @ApiOkResponse({ description: 'List of shipping methods' })
  async listMethods() {
    const r = await this.adminService.listMethods();
    return ResponseUtil.success(r, 'Shipping methods retrieved');
  }

  @Get('methods/:id')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'Get shipping method' })
  @ApiOkResponse({ description: 'Shipping method details' })
  async getMethod(@Param('id') id: string) {
    const r = await this.adminService.getMethod(id);
    return ResponseUtil.success(r, 'Shipping method retrieved');
  }

  @Put('methods/:id')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'update' })
  @ApiOperation({ summary: 'Update shipping method' })
  @ApiOkResponse({ description: 'Shipping method updated' })
  async updateMethod(@Param('id') id: string, @Body() payload: Partial<CreateShippingMethodDto>) {
    const r = await this.adminService.updateMethod(id, payload);
    return ResponseUtil.success(r, 'Shipping method updated');
  }

  @Delete('methods/:id')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'delete' })
  @ApiOperation({ summary: 'Delete shipping method' })
  @ApiOkResponse({ description: 'Shipping method deleted' })
  async deleteMethod(@Param('id') id: string) {
    const ok = await this.adminService.deleteMethod(id);
    return ResponseUtil.success({ deleted: ok }, 'Shipping method deleted');
  }

  @Get('methods/:id/rates')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'List shipping rates for a method (nested route)' })
  @ApiOkResponse({ description: 'List of shipping rates for the method' })
  async listRatesForMethod(@Param('id') id: string) {
    const rows = await this.adminService.listRates(id);
    return ResponseUtil.success(rows, 'Shipping rates retrieved');
  }

  @Post('methods/:id/rates')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'create' })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a shipping rate for a method (nested route)' })
  @ApiBody({ type: CreateMethodShippingRateDto })
  @ApiCreatedResponse({ description: 'Shipping rate created' })
  async createRateForMethod(@Param('id') id: string, @Body() payload: CreateMethodShippingRateDto) {
    const r = await this.adminService.createRate({
      methodId: id,
      calculationType: payload.calculationType,
      price: payload.price,
      minWeight: payload.minWeight,
      maxWeight: payload.maxWeight,
      minSubtotal: payload.minSubtotal,
      maxSubtotal: payload.maxSubtotal,
      pricePerUnit: payload.pricePerUnit,
      priority: payload.priority,
      metaJson: payload.metaJson,
    } as CreateShippingRateDto);
    return ResponseUtil.created(r, 'Shipping rate created');
  }

  // Rates
  @Post('rates')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'create' })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a shipping rate' })
  @ApiBody({ type: CreateShippingRateDto })
  @ApiCreatedResponse({ description: 'Shipping rate created' })
  async createRate(@Body() payload: CreateShippingRateDto) {
    const r = await this.adminService.createRate(payload);
    return ResponseUtil.created(r, 'Shipping rate created');
  }

  @Get('rates')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'List shipping rates' })
  @ApiOkResponse({ description: 'List of shipping rates' })
  async listRates() {
    const r = await this.adminService.listRates();
    return ResponseUtil.success(r, 'Shipping rates retrieved');
  }

  @Get('rates/:id')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'Get shipping rate' })
  @ApiOkResponse({ description: 'Shipping rate details' })
  async getRate(@Param('id') id: string) {
    const r = await this.adminService.getRate(id);
    return ResponseUtil.success(r, 'Shipping rate retrieved');
  }

  @Put('rates/:id')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'update' })
  @ApiOperation({ summary: 'Update shipping rate' })
  @ApiOkResponse({ description: 'Shipping rate updated' })
  async updateRate(@Param('id') id: string, @Body() payload: Partial<CreateShippingRateDto>) {
    const r = await this.adminService.updateRate(id, payload);
    return ResponseUtil.success(r, 'Shipping rate updated');
  }

  @Delete('rates/:id')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'delete' })
  @ApiOperation({ summary: 'Delete shipping rate' })
  @ApiOkResponse({ description: 'Shipping rate deleted' })
  async deleteRate(@Param('id') id: string) {
    const ok = await this.adminService.deleteRate(id);
    return ResponseUtil.success({ deleted: ok }, 'Shipping rate deleted');
  }
}
