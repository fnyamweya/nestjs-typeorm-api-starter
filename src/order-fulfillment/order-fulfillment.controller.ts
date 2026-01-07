import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  Req,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiExtraModels,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { RequestWithUser } from 'src/auth/interfaces/user.interface';
import { ResponseUtil } from 'src/common/utils/response.util';
import { CreateOrderFulfillmentDto } from './dto/create-fulfillment.dto';
import { UpdateOrderFulfillmentDto } from './dto/update-fulfillment.dto';
import {
  OrderFulfillmentResponseDto,
  OrderFulfillmentsListResponseDto,
} from './dto/order-fulfillment-response.dto';
import { OrderFulfillmentService } from './order-fulfillment.service';

@Controller('orders/:orderId/fulfillments')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))
@ApiTags('Order Fulfillments')
@ApiBearerAuth('access-token')
@ApiExtraModels(OrderFulfillmentResponseDto, OrderFulfillmentsListResponseDto)
export class OrderFulfillmentController {
  constructor(private readonly fulfillmentService: OrderFulfillmentService) {}

  @Get()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ORDERS, permission: 'read' })
  @ApiOperation({ summary: 'List fulfillments for an order' })
  @ApiOkResponse({ description: 'Fulfillments retrieved successfully', type: OrderFulfillmentsListResponseDto })
  async list(@Param('orderId') orderId: string) {
    const data = await this.fulfillmentService.listForOrder(orderId);
    return ResponseUtil.success(data, 'Fulfillments retrieved successfully');
  }

  @Get('/:fulfillmentId')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ORDERS, permission: 'read' })
  @ApiOperation({ summary: 'Get fulfillment by id for an order' })
  @ApiOkResponse({ description: 'Fulfillment retrieved successfully', type: OrderFulfillmentResponseDto })
  async get(@Param('orderId') orderId: string, @Param('fulfillmentId') fulfillmentId: string) {
    const data = await this.fulfillmentService.getForOrder(orderId, fulfillmentId);
    return ResponseUtil.success(data, 'Fulfillment retrieved successfully');
  }

  @Post()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ORDERS, permission: 'update' })
  @ApiOperation({ summary: 'Create a fulfillment (shipment) for an order' })
  @ApiBody({ type: CreateOrderFulfillmentDto })
  @ApiCreatedResponse({ description: 'Fulfillment created successfully', type: OrderFulfillmentResponseDto })
  async create(
    @Param('orderId') orderId: string,
    @Body() payload: CreateOrderFulfillmentDto,
    @Req() req: RequestWithUser,
  ) {
    const actor = req?.user
      ? ({ type: 'user', id: (req.user as any).id, email: (req.user as any).email, roleId: (req.user as any).roleId } as any)
      : null;

    const data = await this.fulfillmentService.createForOrder(orderId, payload, actor);
    return ResponseUtil.created(data, 'Fulfillment created successfully');
  }

  @Patch('/:fulfillmentId')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ORDERS, permission: 'update' })
  @ApiOperation({ summary: 'Update fulfillment status/tracking/timestamps' })
  @ApiBody({ type: UpdateOrderFulfillmentDto })
  @ApiOkResponse({ description: 'Fulfillment updated successfully', type: OrderFulfillmentResponseDto })
  async update(
    @Param('orderId') orderId: string,
    @Param('fulfillmentId') fulfillmentId: string,
    @Body() payload: UpdateOrderFulfillmentDto,
    @Req() req: RequestWithUser,
  ) {
    const actor = req?.user
      ? ({ type: 'user', id: (req.user as any).id, email: (req.user as any).email, roleId: (req.user as any).roleId } as any)
      : null;

    const data = await this.fulfillmentService.updateForOrder(orderId, fulfillmentId, payload, actor);
    return ResponseUtil.updated(data, 'Fulfillment updated successfully');
  }
}
