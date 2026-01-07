import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { CustomerTierService } from './customer-tier.service';
import { CreateCustomerTierDto } from './dto/create-customer-tier.dto';
import { UpdateCustomerTierDto } from './dto/update-customer-tier.dto';
import { CreateCustomerTierRuleDto } from './dto/create-customer-tier-rule.dto';
import { UpdateCustomerTierRuleDto } from './dto/update-customer-tier-rule.dto';
import { SetCustomerTierOverrideDto } from './dto/set-customer-tier-override.dto';

@Controller('customer-tiers')
@ApiTags('Customer Tiers')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class CustomerTierController {
  constructor(private readonly customerTierService: CustomerTierService) {}

  @Get()
  @RequirePermissions({
    module: PermissionModule.CUSTOMER_TIERS,
    permission: 'read',
  })
  @ApiOkResponse({ description: 'Customer tiers retrieved successfully' })
  async listTiers() {
    const data = await this.customerTierService.listTiers();
    return ResponseUtil.success(data, 'Customer tiers retrieved successfully');
  }

  @Post()
  @RequirePermissions({
    module: PermissionModule.CUSTOMER_TIERS,
    permission: 'create',
  })
  @ApiOkResponse({ description: 'Customer tier created successfully' })
  async createTier(@Body() payload: CreateCustomerTierDto) {
    const data = await this.customerTierService.createTier(payload);
    return ResponseUtil.success(data, 'Customer tier created successfully');
  }

  @Patch(':code')
  @RequirePermissions({
    module: PermissionModule.CUSTOMER_TIERS,
    permission: 'update',
  })
  @ApiOkResponse({ description: 'Customer tier updated successfully' })
  async updateTier(
    @Param('code') code: string,
    @Body() payload: UpdateCustomerTierDto,
  ) {
    const data = await this.customerTierService.updateTier(code, payload);
    return ResponseUtil.success(data, 'Customer tier updated successfully');
  }

  @Delete(':code')
  @RequirePermissions({
    module: PermissionModule.CUSTOMER_TIERS,
    permission: 'delete',
  })
  @ApiOkResponse({ description: 'Customer tier deleted successfully' })
  async deleteTier(@Param('code') code: string) {
    await this.customerTierService.deleteTier(code);
    return ResponseUtil.success(null, 'Customer tier deleted successfully');
  }

  @Get('rules')
  @RequirePermissions({
    module: PermissionModule.CUSTOMER_TIERS,
    permission: 'read',
  })
  @ApiOkResponse({ description: 'Customer tier rules retrieved successfully' })
  async listRules() {
    const data = await this.customerTierService.listRules();
    return ResponseUtil.success(
      data,
      'Customer tier rules retrieved successfully',
    );
  }

  @Post('rules')
  @RequirePermissions({
    module: PermissionModule.CUSTOMER_TIERS,
    permission: 'create',
  })
  @ApiOkResponse({ description: 'Customer tier rule created successfully' })
  async createRule(@Body() payload: CreateCustomerTierRuleDto) {
    const data = await this.customerTierService.createRule(payload);
    return ResponseUtil.success(
      data,
      'Customer tier rule created successfully',
    );
  }

  @Patch('rules/:id')
  @RequirePermissions({
    module: PermissionModule.CUSTOMER_TIERS,
    permission: 'update',
  })
  @ApiOkResponse({ description: 'Customer tier rule updated successfully' })
  async updateRule(
    @Param('id') id: string,
    @Body() payload: UpdateCustomerTierRuleDto,
  ) {
    const data = await this.customerTierService.updateRule(id, payload);
    return ResponseUtil.success(
      data,
      'Customer tier rule updated successfully',
    );
  }

  @Delete('rules/:id')
  @RequirePermissions({
    module: PermissionModule.CUSTOMER_TIERS,
    permission: 'delete',
  })
  @ApiOkResponse({ description: 'Customer tier rule deleted successfully' })
  async deleteRule(@Param('id') id: string) {
    await this.customerTierService.deleteRule(id);
    return ResponseUtil.success(
      null,
      'Customer tier rule deleted successfully',
    );
  }

  @Post('customers/:userId/override')
  @RequirePermissions({
    module: PermissionModule.CUSTOMER_TIERS,
    permission: 'update',
  })
  @ApiOkResponse({ description: 'Customer tier override updated successfully' })
  async setOverride(
    @Param('userId') userId: string,
    @Body() payload: SetCustomerTierOverrideDto,
  ) {
    await this.customerTierService.setCustomerTierOverride(
      userId,
      payload.tierCode,
    );
    return ResponseUtil.success(
      null,
      'Customer tier override updated successfully',
    );
  }
}
