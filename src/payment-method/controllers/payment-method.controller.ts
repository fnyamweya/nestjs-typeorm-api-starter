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
import { CreatePaymentMethodDto } from '../dto/create-payment-method.dto';
import { UpdatePaymentMethodDto } from '../dto/update-payment-method.dto';
import { ListPaymentMethodsDto } from '../dto/list-payment-methods.dto';
import { PaymentMethodService } from '../services/payment-method.service';

@Controller('payment-methods')
@ApiTags('Payment Methods')
@ApiBearerAuth('access-token')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class PaymentMethodController {
  constructor(private readonly methodService: PaymentMethodService) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.PAYMENT_METHODS,
    permission: 'create',
  })
  @ApiCreatedResponse({ description: 'Payment method created' })
  async create(@Body() payload: CreatePaymentMethodDto) {
    const row = await this.methodService.create(payload);
    return ResponseUtil.created(row, 'Payment method created');
  }

  @Get()
  @RequirePermissions({
    module: PermissionModule.PAYMENT_METHODS,
    permission: 'read',
  })
  @ApiOkResponse({ description: 'Payment methods retrieved' })
  async list(@Query() query: ListPaymentMethodsDto) {
    const rows = await this.methodService.list(query);
    return ResponseUtil.success(rows, 'Payment methods retrieved');
  }

  @Get(':id')
  @RequirePermissions({
    module: PermissionModule.PAYMENT_METHODS,
    permission: 'read',
  })
  @ApiOkResponse({ description: 'Payment method retrieved' })
  async get(@Param('id') id: string) {
    const row = await this.methodService.getById(id);
    return ResponseUtil.success(row, 'Payment method retrieved');
  }

  @Patch(':id')
  @RequirePermissions({
    module: PermissionModule.PAYMENT_METHODS,
    permission: 'update',
  })
  @ApiOkResponse({ description: 'Payment method updated' })
  async update(
    @Param('id') id: string,
    @Body() payload: UpdatePaymentMethodDto,
  ) {
    const row = await this.methodService.update(id, payload);
    return ResponseUtil.success(row, 'Payment method updated');
  }

  @Delete(':id')
  @RequirePermissions({
    module: PermissionModule.PAYMENT_METHODS,
    permission: 'delete',
  })
  @ApiOkResponse({ description: 'Payment method deleted' })
  async delete(@Param('id') id: string) {
    const res = await this.methodService.delete(id);
    return ResponseUtil.success(res, 'Payment method deleted');
  }
}
