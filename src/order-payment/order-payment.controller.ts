import {
  Body,
  Controller,
  Get,
  Param,
  Post,
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
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PermissionsGuard } from '../auth/guards/permissions.guard';
import { RequirePermissions } from '../auth/decorators/permissions.decorator';
import { PermissionModule } from '../auth/entities/permission.entity';
import { ResponseUtil } from '../common/utils/response.util';
import { CreateOrderPaymentDto } from './dto/create-order-payment.dto';
import { OrderPaymentSummaryDto } from './dto/order-payment-summary.dto';
import { OrderPaymentService } from './order-payment.service';

@Controller('orders/:orderId/payments')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@ApiTags('Order Payments')
@ApiBearerAuth('access-token')
@ApiExtraModels(OrderPaymentSummaryDto)
export class OrderPaymentController {
  constructor(private readonly orderPaymentService: OrderPaymentService) {}

  @Get()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ORDERS, permission: 'read' })
  @ApiOperation({ summary: 'List payments for an order' })
  @ApiOkResponse({ description: 'Payments fetched successfully' })
  async list(@Param('orderId') orderId: string) {
    const payments = await this.orderPaymentService.listForOrder(orderId);
    return ResponseUtil.success(payments, 'Payments fetched successfully');
  }

  @Get('summary')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ORDERS, permission: 'read' })
  @ApiOperation({ summary: 'Get payment summary for an order' })
  @ApiOkResponse({
    description: 'Payment summary fetched successfully',
    type: OrderPaymentSummaryDto,
  })
  async summary(@Param('orderId') orderId: string) {
    const summary = await this.orderPaymentService.getSummary(orderId);
    return ResponseUtil.success(
      summary,
      'Payment summary fetched successfully',
    );
  }

  @Post()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions({ module: PermissionModule.ORDERS, permission: 'update' })
  @ApiOperation({ summary: 'Record a payment for an order (with allocations)' })
  @ApiBody({
    type: CreateOrderPaymentDto,
    examples: {
      capturePendingNoAllocations: {
        summary: 'Capture (pending) - defaults to whole order',
        description:
          'Records a pending payment initiation. If allocations are omitted, the service allocates the full amount to the order automatically.',
        value: {
          type: 'CAPTURE',
          status: 'PENDING',
          provider: 'MNO',
          method: 'MOBILE_MONEY',
          amount: 150000,
          currency: 'KES',
          externalRef: 'mno_txn_123',
          initiatedAt: '2026-01-03T10:21:00Z',
          metaJson: {
            msisdn: '+254700000000',
            checkoutRequestId: 'ws_CO_123456',
          },
        },
      },
      captureSucceededSplitAcrossItems: {
        summary: 'Capture (succeeded) - split across order items',
        description:
          'Records a successful capture and explicitly allocates amounts across multiple order items (sum must equal payment amount).',
        value: {
          type: 'CAPTURE',
          status: 'SUCCEEDED',
          provider: 'CARD',
          method: 'VISA',
          amount: 1499,
          currency: 'KES',
          externalRef: 'ch_3Pxxx',
          confirmedAt: '2026-01-03T10:21:20Z',
          allocations: [
            {
              appliesTo: 'ORDER_ITEM',
              orderItemId: '11111111-1111-1111-1111-111111111111',
              amount: 999,
              currency: 'KES',
              metaJson: { note: 'Item A portion' },
            },
            {
              appliesTo: 'ORDER_ITEM',
              orderItemId: '22222222-2222-2222-2222-222222222222',
              amount: 500,
              currency: 'KES',
              metaJson: { note: 'Item B portion' },
            },
          ],
          metaJson: {
            gateway: 'stripe',
            receiptEmail: 'buyer@example.com',
          },
        },
      },
      refundSucceededItemLevel: {
        summary: 'Refund (succeeded) - item-level refund allocation',
        description:
          'Records a refund. Amounts are provided as positive numbers; the system treats REFUND/REVERSAL as negative in summaries.',
        value: {
          type: 'REFUND',
          status: 'SUCCEEDED',
          provider: 'CARD',
          method: 'VISA',
          amount: 500,
          currency: 'KES',
          externalRef: 'rf_3Pxxx',
          confirmedAt: '2026-01-04T08:30:00Z',
          allocations: [
            {
              appliesTo: 'ORDER_ITEM',
              orderItemId: '22222222-2222-2222-2222-222222222222',
              amount: 500,
              currency: 'KES',
              metaJson: { reason: 'Returned item' },
            },
          ],
          metaJson: {
            reasonCode: 'RETURN',
            note: 'Customer returned one item',
          },
        },
      },
      adjustmentNegative: {
        summary: 'Adjustment (succeeded) - negative correction',
        description:
          'Records an adjustment (can be negative). Useful for fee corrections, rounding, or manual ledger fixes. Negative amounts are only allowed for ADJUSTMENT.',
        value: {
          type: 'ADJUSTMENT',
          status: 'SUCCEEDED',
          provider: 'INTERNAL',
          method: 'MANUAL',
          amount: -25,
          currency: 'KES',
          externalRef: 'adj_001',
          confirmedAt: '2026-01-05T09:00:00Z',
          allocations: [
            {
              appliesTo: 'ORDER',
              amount: -25,
              currency: 'KES',
              metaJson: { note: 'Rounding correction' },
            },
          ],
          metaJson: {
            actor: 'system',
            reason: 'rounding',
          },
        },
      },
    },
  })
  @ApiCreatedResponse({ description: 'Payment recorded successfully' })
  async create(
    @Param('orderId') orderId: string,
    @Body() payload: CreateOrderPaymentDto,
  ) {
    const payment = await this.orderPaymentService.createForOrder(
      orderId,
      payload,
    );
    return ResponseUtil.created(payment, 'Payment recorded successfully');
  }
}
