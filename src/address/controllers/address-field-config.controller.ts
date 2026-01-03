import {
  Body,
  Controller,
  Get,
  Put,
  Query,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { ResponseUtil } from 'src/common/utils/response.util';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { UpsertAddressFieldConfigDto } from '../dto/upsert-address-field-config.dto';
import { AddressFieldConfigService } from '../services/address-field-config.service';

@Controller('addresses/field-config')
@ApiTags('Address Config')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))
export class AddressFieldConfigController {
  constructor(private readonly service: AddressFieldConfigService) {}

  @Get()
  @ApiOkResponse({ description: 'Address field config retrieved' })
  async get(@Query('countryCode') countryCode: string) {
    const row = await this.service.getActive(countryCode?.toUpperCase() || 'KE');
    return ResponseUtil.success(row, 'Address field config retrieved');
  }

  @Put()
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ADDRESS_CONFIG, permission: 'update' })
  @ApiOkResponse({ description: 'Address field config saved' })
  async upsert(
    @Query('countryCode') countryCode: string,
    @Body() payload: UpsertAddressFieldConfigDto,
  ) {
    const row = await this.service.upsertActive(
      countryCode?.toUpperCase() || 'KE',
      payload.schema,
    );
    return ResponseUtil.success(row, 'Address field config saved');
  }
}
