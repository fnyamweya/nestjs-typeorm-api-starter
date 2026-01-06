import { Body, Controller, Post, UseGuards, UsePipes, ValidationPipe } from '@nestjs/common';
import { ApiTags, ApiCreatedResponse, ApiBearerAuth, ApiBody, ApiExtraModels, ApiOperation } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { OrderService } from '../services/order.service';
import { CreateOrderDto } from '../dto/create-order.dto';
import { ResponseUtil } from 'src/common/utils/response.util';
import { OrderCreatedResponseDto } from '../dto/order-created-response.dto';

@Controller('orders')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))
@ApiTags('Orders')
@ApiBearerAuth('access-token')
@ApiExtraModels(OrderCreatedResponseDto)
export class OrderController {
  constructor(private readonly orderService: OrderService) {}

  @Post()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ORDERS, permission: 'create' })
  @ApiOperation({ summary: 'Create an order' })
  @ApiBody({ type: CreateOrderDto })
  @ApiCreatedResponse({ description: 'Order created successfully', type: OrderCreatedResponseDto })
  async create(@Body() payload: CreateOrderDto) {
    const order = await this.orderService.create(payload);
    return ResponseUtil.created(order, 'Order created successfully');
  }
}
