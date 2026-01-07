import { Controller, Get, Param, Query, UseGuards, UsePipes, ValidationPipe } from '@nestjs/common';
import { ApiBearerAuth, ApiExtraModels, ApiOkResponse, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { OrderEventTargetType } from './order-events.types';
import { OrderEventsListResponseDto } from './dto/order-event-response.dto';
import { OrderEventsService } from './order-events.service';

@Controller('orders/:orderId/events')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))
@ApiTags('Order Events')
@ApiBearerAuth('access-token')
@ApiExtraModels(OrderEventsListResponseDto)
export class OrderEventsController {
  constructor(private readonly orderEvents: OrderEventsService) {}

  @Get()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ORDERS, permission: 'read' })
  @ApiOperation({ summary: 'List events for an order (includes order items, fulfillments, packages)' })
  @ApiQuery({ name: 'targetType', required: false, enum: OrderEventTargetType })
  @ApiQuery({ name: 'targetId', required: false, type: String })
  @ApiOkResponse({ description: 'Order events retrieved successfully', type: OrderEventsListResponseDto })
  async list(
    @Param('orderId') orderId: string,
    @Query('targetType') targetType?: OrderEventTargetType,
    @Query('targetId') targetId?: string,
  ) {
    const data = await this.orderEvents.listForOrder(orderId, { targetType, targetId });
    return ResponseUtil.success(data, 'Order events retrieved successfully');
  }
}
