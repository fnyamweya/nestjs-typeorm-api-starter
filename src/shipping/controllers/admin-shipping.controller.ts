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
import { CreateShippingMethodDto } from '../dto/create-shipping-method.dto';
import { CreateShippingRateDto } from '../dto/create-shipping-rate.dto';
import { ApiBearerAuth, ApiBody, ApiCreatedResponse, ApiTags, ApiOkResponse, ApiOperation } from '@nestjs/swagger';
import { ResponseUtil } from 'src/common/utils/response.util';

@Controller('admin/shipping')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@ApiTags('Admin Shipping')
@ApiBearerAuth('access-token')
export class AdminShippingController {
  constructor(private readonly adminService: ShippingAdminService) {}

  // Zones
  @Post('zones')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'create' })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a shipping zone' })
  @ApiBody({ type: CreateShippingZoneDto })
  @ApiCreatedResponse({ description: 'Shipping zone created' })
  async createZone(@Body() payload: CreateShippingZoneDto) {
    const z = await this.adminService.createZone(payload);
    return ResponseUtil.created(z, 'Shipping zone created');
  }

  @Get('zones')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({ summary: 'List shipping zones' })
  @ApiOkResponse({ description: 'List of shipping zones' })
  async listZones() {
    const z = await this.adminService.listZones();
    return ResponseUtil.success(z, 'Shipping zones retrieved');
  }

  @Get('zones/:id')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({ summary: 'Get shipping zone' })
  @ApiOkResponse({ description: 'Shipping zone details' })
  async getZone(@Param('id') id: string) {
    const z = await this.adminService.getZone(id);
    return ResponseUtil.success(z, 'Shipping zone retrieved');
  }

  @Put('zones/:id')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'update' })
  @ApiOperation({ summary: 'Update shipping zone' })
  @ApiOkResponse({ description: 'Shipping zone updated' })
  async updateZone(@Param('id') id: string, @Body() payload: Partial<CreateShippingZoneDto>) {
    const z = await this.adminService.updateZone(id, payload);
    return ResponseUtil.success(z, 'Shipping zone updated');
  }

  @Delete('zones/:id')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'delete' })
  @ApiOperation({ summary: 'Delete shipping zone' })
  @ApiOkResponse({ description: 'Shipping zone deleted' })
  async deleteZone(@Param('id') id: string) {
    const ok = await this.adminService.deleteZone(id);
    return ResponseUtil.success({ deleted: ok }, 'Shipping zone deleted');
  }

  // Methods
  @Post('methods')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'create' })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a shipping method' })
  @ApiBody({ type: CreateShippingMethodDto })
  @ApiCreatedResponse({ description: 'Shipping method created' })
  async createMethod(@Body() payload: CreateShippingMethodDto) {
    const r = await this.adminService.createMethod(payload);
    return ResponseUtil.created(r, 'Shipping method created');
  }

  @Get('methods')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({ summary: 'List shipping methods' })
  @ApiOkResponse({ description: 'List of shipping methods' })
  async listMethods() {
    const r = await this.adminService.listMethods();
    return ResponseUtil.success(r, 'Shipping methods retrieved');
  }

  @Get('methods/:id')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({ summary: 'Get shipping method' })
  @ApiOkResponse({ description: 'Shipping method details' })
  async getMethod(@Param('id') id: string) {
    const r = await this.adminService.getMethod(id);
    return ResponseUtil.success(r, 'Shipping method retrieved');
  }

  @Put('methods/:id')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'update' })
  @ApiOperation({ summary: 'Update shipping method' })
  @ApiOkResponse({ description: 'Shipping method updated' })
  async updateMethod(@Param('id') id: string, @Body() payload: Partial<CreateShippingMethodDto>) {
    const r = await this.adminService.updateMethod(id, payload);
    return ResponseUtil.success(r, 'Shipping method updated');
  }

  @Delete('methods/:id')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'delete' })
  @ApiOperation({ summary: 'Delete shipping method' })
  @ApiOkResponse({ description: 'Shipping method deleted' })
  async deleteMethod(@Param('id') id: string) {
    const ok = await this.adminService.deleteMethod(id);
    return ResponseUtil.success({ deleted: ok }, 'Shipping method deleted');
  }

  // Rates
  @Post('rates')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'create' })
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a shipping rate' })
  @ApiBody({ type: CreateShippingRateDto })
  @ApiCreatedResponse({ description: 'Shipping rate created' })
  async createRate(@Body() payload: CreateShippingRateDto) {
    const r = await this.adminService.createRate(payload);
    return ResponseUtil.created(r, 'Shipping rate created');
  }

  @Get('rates')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({ summary: 'List shipping rates' })
  @ApiOkResponse({ description: 'List of shipping rates' })
  async listRates() {
    const r = await this.adminService.listRates();
    return ResponseUtil.success(r, 'Shipping rates retrieved');
  }

  @Get('rates/:id')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'read' })
  @ApiOperation({ summary: 'Get shipping rate' })
  @ApiOkResponse({ description: 'Shipping rate details' })
  async getRate(@Param('id') id: string) {
    const r = await this.adminService.getRate(id);
    return ResponseUtil.success(r, 'Shipping rate retrieved');
  }

  @Put('rates/:id')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'update' })
  @ApiOperation({ summary: 'Update shipping rate' })
  @ApiOkResponse({ description: 'Shipping rate updated' })
  async updateRate(@Param('id') id: string, @Body() payload: Partial<CreateShippingRateDto>) {
    const r = await this.adminService.updateRate(id, payload);
    return ResponseUtil.success(r, 'Shipping rate updated');
  }

  @Delete('rates/:id')
  @RequirePermissions({ module: PermissionModule.SETTINGS, permission: 'delete' })
  @ApiOperation({ summary: 'Delete shipping rate' })
  @ApiOkResponse({ description: 'Shipping rate deleted' })
  async deleteRate(@Param('id') id: string) {
    const ok = await this.adminService.deleteRate(id);
    return ResponseUtil.success({ deleted: ok }, 'Shipping rate deleted');
  }
}
