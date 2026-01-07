import {
  Body,
  Controller,
  Delete,
  Get,
  NotFoundException,
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
import { AttachZoneShippingMethodDto } from '../dto/attach-zone-shipping-method.dto';
import { CreateMethodShippingRateDto } from '../dto/create-method-shipping-rate.dto';
import { CreateShippingProviderDto } from '../dto/create-shipping-provider.dto';
import { UpdateShippingProviderDto } from '../dto/update-shipping-provider.dto';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiTags,
  ApiOkResponse,
  ApiOperation,
} from '@nestjs/swagger';
import { ResponseUtil } from 'src/common/utils/response.util';

@Controller('shipping')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@ApiTags('Shipping')
@ApiBearerAuth('access-token')
export class AdminShippingController {
  constructor(private readonly adminService: ShippingAdminService) {}

  // Zones
  @Post('zones')
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'create',
  })
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
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Update shipping zone' })
  @ApiOkResponse({ description: 'Shipping zone updated' })
  async updateZone(
    @Param('id') id: string,
    @Body() payload: Partial<CreateShippingZoneDto>,
  ) {
    const z = await this.adminService.updateZone(id, payload);
    return ResponseUtil.success(z, 'Shipping zone updated');
  }

  @Delete('zones/:id')
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'delete',
  })
  @ApiOperation({ summary: 'Delete shipping zone' })
  @ApiOkResponse({ description: 'Shipping zone deleted' })
  async deleteZone(@Param('id') id: string) {
    const ok = await this.adminService.deleteZone(id);
    return ResponseUtil.success({ deleted: ok }, 'Shipping zone deleted');
  }

  @Get('zones/:id/locations')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'List locations attached to a shipping zone' })
  @ApiOkResponse({
    description: 'List of shipping zone locations for the zone',
  })
  async listZoneLocationsForZone(@Param('id') id: string) {
    const rows = await this.adminService.listZoneLocations(id);
    return ResponseUtil.success(rows, 'Shipping zone locations retrieved');
  }

  @Post('zones/:id/locations')
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'create',
  })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Attach a location to a shipping zone (nested route)',
  })
  @ApiBody({ type: AttachShippingZoneLocationDto })
  @ApiCreatedResponse({ description: 'Shipping zone location created' })
  async createZoneLocationForZone(
    @Param('id') id: string,
    @Body() payload: AttachShippingZoneLocationDto,
  ) {
    const row = await this.adminService.createZoneLocation({
      zoneId: id,
      locationId: payload.locationId,
      countryCode: payload.countryCode,
      type: payload.type,
    });
    return ResponseUtil.created(row, 'Shipping zone location created');
  }

  @Get('zones/:id/methods')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'List shipping methods for a zone (nested route)' })
  @ApiOkResponse({ description: 'List of shipping methods for the zone' })
  async listMethodsForZone(@Param('id') id: string) {
    const rows = await this.adminService.listMethodsForZone(id);
    return ResponseUtil.success(rows, 'Shipping zone methods retrieved');
  }

  @Post('zones/:id/methods')
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'create',
  })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Attach a global shipping method to a zone (nested route)',
  })
  @ApiBody({ type: AttachZoneShippingMethodDto })
  @ApiCreatedResponse({ description: 'Shipping method attached' })
  async createMethodForZone(
    @Param('id') id: string,
    @Body() payload: AttachZoneShippingMethodDto,
  ) {
    const r = await this.adminService.attachMethodToZone({
      zoneId: id,
      shippingMethodId: payload.shippingMethodId,
      isActive: payload.isActive,
    });
    return ResponseUtil.created(r, 'Shipping method attached to zone');
  }

  // Providers
  @Get('providers')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'List shipping providers' })
  @ApiOkResponse({ description: 'List of shipping providers' })
  async listProviders() {
    const rows = await this.adminService.listProviders();
    return ResponseUtil.success(rows, 'Shipping providers retrieved');
  }

  @Post('providers')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'create' })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a shipping provider' })
  @ApiCreatedResponse({ description: 'Shipping provider created' })
  async createProvider(
    @Body() payload: CreateShippingProviderDto,
  ) {
    const row = await this.adminService.createProvider(payload as any);
    return ResponseUtil.created(row, 'Shipping provider created');
  }

  @Get('providers/:id')
  @RequirePermissions({ module: PermissionModule.SHIPPING, permission: 'read' })
  @ApiOperation({ summary: 'Get shipping provider' })
  @ApiOkResponse({ description: 'Shipping provider details' })
  async getProvider(@Param('id') id: string) {
    const row = await this.adminService.getProvider(id);
    return ResponseUtil.success(row, 'Shipping provider retrieved');
  }

  @Put('providers/:id')
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Update shipping provider' })
  @ApiBody({ type: UpdateShippingProviderDto })
  @ApiOkResponse({ description: 'Shipping provider updated' })
  async updateProvider(
    @Param('id') id: string,
    @Body() payload: UpdateShippingProviderDto,
  ) {
    const row = await this.adminService.updateProvider(id, payload as any);
    return ResponseUtil.success(row, 'Shipping provider updated');
  }

  @Delete('providers/:id')
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'delete',
  })
  @ApiOperation({ summary: 'Delete shipping provider' })
  @ApiOkResponse({ description: 'Shipping provider deleted' })
  async deleteProvider(@Param('id') id: string) {
    const ok = await this.adminService.deleteProvider(id);
    return ResponseUtil.success({ deleted: ok }, 'Shipping provider deleted');
  }

  // Zone locations (locationId-based)
  @Post('zone-locations')
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'create',
  })
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
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'delete',
  })
  @ApiOperation({ summary: 'Delete shipping zone location mapping' })
  @ApiOkResponse({ description: 'Shipping zone location deleted' })
  async deleteZoneLocation(@Param('id') id: string) {
    const ok = await this.adminService.deleteZoneLocation(id);
    return ResponseUtil.success(
      { deleted: ok },
      'Shipping zone location deleted',
    );
  }

  // Methods
  @Post('methods')
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'create',
  })
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
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Update shipping method' })
  @ApiOkResponse({ description: 'Shipping method updated' })
  async updateMethod(
    @Param('id') id: string,
    @Body() payload: Partial<CreateShippingMethodDto>,
  ) {
    const r = await this.adminService.updateMethod(id, payload);
    return ResponseUtil.success(r, 'Shipping method updated');
  }

  @Delete('methods/:id')
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'delete',
  })
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
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'create',
  })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a shipping rate for a method (nested route)',
  })
  @ApiBody({ type: CreateMethodShippingRateDto })
  @ApiCreatedResponse({ description: 'Shipping rate created' })
  async createRateForMethod(
    @Param('id') id: string,
    @Body() payload: CreateMethodShippingRateDto,
  ) {
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
      currencyCode: payload.currencyCode,
      channelIds: payload.channelIds,
      metaJson: payload.metaJson,
    } as CreateShippingRateDto);
    return ResponseUtil.created(r, 'Shipping rate created');
  }

  @Put('methods/:id/rates/:rateId')
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'update',
  })
  @ApiOperation({
    summary: 'Update a shipping rate for a method (nested route)',
  })
  @ApiOkResponse({ description: 'Shipping rate updated' })
  async updateRateForMethod(
    @Param('id') id: string,
    @Param('rateId') rateId: string,
    @Body() payload: Partial<CreateShippingRateDto>,
  ) {
    const existing = await this.adminService.getRate(rateId);
    if (existing.methodId !== id) {
      throw new NotFoundException('Shipping rate not found');
    }
    const r = await this.adminService.updateRate(rateId, payload);
    return ResponseUtil.success(r, 'Shipping rate updated');
  }

  @Delete('methods/:id/rates/:rateId')
  @RequirePermissions({
    module: PermissionModule.SHIPPING,
    permission: 'delete',
  })
  @ApiOperation({
    summary: 'Delete a shipping rate for a method (nested route)',
  })
  @ApiOkResponse({ description: 'Shipping rate deleted' })
  async deleteRateForMethod(
    @Param('id') id: string,
    @Param('rateId') rateId: string,
  ) {
    const existing = await this.adminService.getRate(rateId);
    if (existing.methodId !== id) {
      throw new NotFoundException('Shipping rate not found');
    }
    const ok = await this.adminService.deleteRate(rateId);
    return ResponseUtil.success({ deleted: ok }, 'Shipping rate deleted');
  }
}
