import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Put,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { AuthenticatedUser } from 'src/auth/interfaces/user.interface';
import { ResponseUtil } from 'src/common/utils/response.util';
import { CheckoutService } from '../services/checkout.service';
import { CreateCheckoutSessionDto } from '../dto/create-checkout-session.dto';
import { SetCheckoutDeliveryDto } from '../dto/set-checkout-delivery.dto';
import { SetCheckoutShippingMethodDto } from '../dto/set-checkout-shipping-method.dto';

@Controller('checkout/sessions')
@UseGuards(JwtAuthGuard)
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@ApiTags('Checkout')
@ApiBearerAuth('access-token')
export class CheckoutController {
  constructor(private readonly checkoutService: CheckoutService) {}

  @Post()
  @ApiOperation({ summary: 'Create a new checkout session (draft)' })
  @ApiOkResponse({ description: 'Checkout session created' })
  async createSession(
    @CurrentUser() user: AuthenticatedUser,
    @Body() payload: CreateCheckoutSessionDto,
  ) {
    const row = await this.checkoutService.createSession(user.id, payload);
    return ResponseUtil.created(row, 'Checkout session created');
  }

  @Put(':id/delivery')
  @ApiOperation({
    summary: 'Set delivery (shipping address) for a checkout session',
  })
  @ApiOkResponse({ description: 'Delivery updated' })
  async setDelivery(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() payload: SetCheckoutDeliveryDto,
  ) {
    const row = await this.checkoutService.setDelivery(user.id, id, payload);
    return ResponseUtil.success(row, 'Delivery updated');
  }

  @Get(':id/shipping-methods')
  @ApiOperation({
    summary: 'List available shipping methods for this checkout session',
  })
  @ApiOkResponse({ description: 'Shipping methods returned' })
  async shippingMethods(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ) {
    const result = await this.checkoutService.getShippingMethods(user.id, id);
    return ResponseUtil.success(result, 'Shipping methods returned');
  }

  @Put(':id/shipping-method')
  @ApiOperation({
    summary: 'Choose a shipping method for this checkout session',
  })
  @ApiOkResponse({ description: 'Shipping method selected' })
  async setShippingMethod(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
    @Body() payload: SetCheckoutShippingMethodDto,
  ) {
    const result = await this.checkoutService.setShippingMethod(
      user.id,
      id,
      payload,
    );
    return ResponseUtil.success(result, 'Shipping method selected');
  }

  @Get(':id/review')
  @ApiOperation({ summary: 'Get checkout review summary (draft)' })
  @ApiOkResponse({ description: 'Checkout review returned' })
  async review(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ) {
    const result = await this.checkoutService.review(user.id, id);
    return ResponseUtil.success(result, 'Checkout review returned');
  }

  @Post(':id/confirm')
  @ApiOperation({ summary: 'Confirm checkout and create an order' })
  @ApiOkResponse({ description: 'Order created' })
  async confirm(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ) {
    const result = await this.checkoutService.confirm(user.id, id);
    return ResponseUtil.created(result, 'Order created');
  }
}
