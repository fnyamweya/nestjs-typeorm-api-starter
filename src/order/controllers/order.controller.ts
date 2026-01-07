import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Query,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiTags,
  ApiCreatedResponse,
  ApiBearerAuth,
  ApiBody,
  ApiExtraModels,
  ApiOperation,
  ApiOkResponse,
  ApiQuery,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { OrderService } from '../services/order.service';
import { CreateOrderDto } from '../dto/create-order.dto';
import { ResponseUtil } from 'src/common/utils/response.util';
import { OrderCreatedResponseDto } from '../dto/order-created-response.dto';
import { OrderPaymentService } from 'src/order-payment/order-payment.service';
import {
  OrderResponseDto,
  OrdersListResponseDto,
} from '../dto/order-response.dto';

@Controller('orders')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@ApiTags('Orders')
@ApiBearerAuth('access-token')
@ApiExtraModels(
  OrderCreatedResponseDto,
  OrderResponseDto,
  OrdersListResponseDto,
)
export class OrderController {
  constructor(
    private readonly orderService: OrderService,
    private readonly orderPaymentService: OrderPaymentService,
  ) {}

  @Get()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ORDERS, permission: 'read' })
  @ApiOperation({ summary: 'List orders (minimal)' })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number (default 1)',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Page size (default 10)',
  })
  @ApiOkResponse({
    description: 'Orders retrieved successfully',
    type: OrdersListResponseDto,
  })
  async findAll(@Query('page') page = 1, @Query('limit') limit = 10) {
    const safePage = Math.max(1, Number(page) || 1);
    const safeLimit = Math.min(100, Math.max(1, Number(limit) || 10));
    const skip = (safePage - 1) * safeLimit;

    const [data, total] = await this.orderService.findAndCount({
      skip,
      take: safeLimit,
      order: { createdAt: 'DESC' },
    });

    const summaryMap = await this.orderPaymentService.getSummaryMapForOrders(
      data.map((o) => ({ id: o.id, grandTotal: o.grandTotal })),
    );

    const withPaymentSummary = data.map((o) => ({
      ...o,
      paymentSummary:
        summaryMap[o.id] ??
        ({
          capturedTotal: '0.0000',
          adjustedTotal: '0.0000',
          reversedTotal: '0.0000',
          refundedTotal: '0.0000',
          netPaidTotal: '0.0000',
          status: 'PENDING',
        } as any),
    }));

    return ResponseUtil.paginated(
      withPaymentSummary as any,
      total,
      safePage,
      safeLimit,
      'Orders retrieved successfully',
    );
  }

  @Get('/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ORDERS, permission: 'read' })
  @ApiOperation({ summary: 'Get order by id' })
  @ApiOkResponse({
    description: 'Order retrieved successfully',
    type: OrderResponseDto,
  })
  async findOne(@Param('id') id: string) {
    const order = await this.orderService.findOneHydrated(id);
    const summary = await this.orderPaymentService.getSummary(id);
    return ResponseUtil.success(
      {
        ...(order as any),
        paymentSummary: {
          capturedTotal: summary.capturedTotal,
          adjustedTotal: summary.adjustedTotal,
          reversedTotal: summary.reversedTotal,
          refundedTotal: summary.refundedTotal,
          netPaidTotal: summary.netPaidTotal,
          status: summary.status,
        },
      },
      'Order retrieved successfully',
    );
  }

  @Post()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ORDERS, permission: 'create' })
  @ApiOperation({ summary: 'Create an order' })
  @ApiBody({ type: CreateOrderDto })
  @ApiCreatedResponse({
    description: 'Order created successfully',
    type: OrderCreatedResponseDto,
  })
  async create(@Body() payload: CreateOrderDto) {
    const order = await this.orderService.create(payload);
    return ResponseUtil.created(order, 'Order created successfully');
  }
}
