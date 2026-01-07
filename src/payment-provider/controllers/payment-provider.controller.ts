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
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { CreatePaymentProviderDto } from '../dto/create-payment-provider.dto';
import { UpdatePaymentProviderDto } from '../dto/update-payment-provider.dto';
import { ListPaymentProvidersDto } from '../dto/list-payment-providers.dto';
import { PaymentProviderService } from '../services/payment-provider.service';

@Controller('payment-providers')
@ApiTags('Payment Providers')
@ApiBearerAuth('access-token')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class PaymentProviderController {
  constructor(private readonly providerService: PaymentProviderService) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.PAYMENT_PROVIDERS,
    permission: 'create',
  })
  @ApiCreatedResponse({ description: 'Payment provider created' })
  async create(@Body() payload: CreatePaymentProviderDto) {
    const row = await this.providerService.create(payload);
    return ResponseUtil.created(row, 'Payment provider created');
  }

  @Get()
  @RequirePermissions({
    module: PermissionModule.PAYMENT_PROVIDERS,
    permission: 'read',
  })
  @ApiOkResponse({ description: 'Payment providers retrieved' })
  async list(@Query() query: ListPaymentProvidersDto) {
    const rows = await this.providerService.list(query);
    return ResponseUtil.success(rows, 'Payment providers retrieved');
  }

  @Get(':id')
  @RequirePermissions({
    module: PermissionModule.PAYMENT_PROVIDERS,
    permission: 'read',
  })
  @ApiOkResponse({ description: 'Payment provider retrieved' })
  async get(@Param('id') id: string) {
    const row = await this.providerService.getById(id);
    return ResponseUtil.success(row, 'Payment provider retrieved');
  }

  @Patch(':id')
  @RequirePermissions({
    module: PermissionModule.PAYMENT_PROVIDERS,
    permission: 'update',
  })
  @ApiOkResponse({ description: 'Payment provider updated' })
  async update(
    @Param('id') id: string,
    @Body() payload: UpdatePaymentProviderDto,
  ) {
    const row = await this.providerService.update(id, payload);
    return ResponseUtil.success(row, 'Payment provider updated');
  }

  @Delete(':id')
  @RequirePermissions({
    module: PermissionModule.PAYMENT_PROVIDERS,
    permission: 'delete',
  })
  @ApiOkResponse({ description: 'Payment provider deleted' })
  async delete(@Param('id') id: string) {
    const res = await this.providerService.delete(id);
    return ResponseUtil.success(res, 'Payment provider deleted');
  }
}
