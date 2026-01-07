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
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { UpsertCountryConfigDto } from '../dto/upsert-country-config.dto';
import { CountryConfigService } from '../country-config.service';

@Controller('countries/config')
@ApiTags('Countries: Config')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
export class CountryConfigController {
  constructor(private readonly service: CountryConfigService) {}

  @Get()
  @ApiOkResponse({ description: 'Country config retrieved' })
  async get(@Query('countryCode') countryCode: string) {
    const row = await this.service.getActive(
      countryCode?.toUpperCase() || 'KE',
    );
    return ResponseUtil.success(row, 'Country config retrieved');
  }

  @Put()
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @ApiOkResponse({ description: 'Country config saved' })
  async upsert(
    @Query('countryCode') countryCode: string,
    @Body() payload: UpsertCountryConfigDto,
  ) {
    const row = await this.service.upsertActive(
      countryCode?.toUpperCase() || 'KE',
      payload.config,
    );
    return ResponseUtil.success(row, 'Country config saved');
  }
}
