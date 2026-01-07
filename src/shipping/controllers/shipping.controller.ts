import {
  Body,
  Controller,
  Post,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { ResponseUtil } from '../../common/utils/response.util';
import { GetShippingQuotesDto } from '../dto/get-shipping-quotes.dto';
import { ShippingQuotesService } from '../services/shipping-quotes.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';

@Controller('shipping')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@ApiTags('Shipping')
@ApiBearerAuth('access-token')
export class ShippingController {
  constructor(private readonly shippingQuotesService: ShippingQuotesService) {}

  @Post('quotes')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Get shipping quotes for a cart (pre-checkout)' })
  @ApiBody({ type: GetShippingQuotesDto })
  @ApiOkResponse({ description: 'Shipping quotes returned successfully' })
  async quotes(@Body() payload: GetShippingQuotesDto) {
    const quotes = await this.shippingQuotesService.getQuotes({
      shippingLocationId: payload.shippingLocationId,
      orderItems: payload.orderItems,
      priceListId: payload.priceListId,
      currencyCode: payload.currencyCode,
      salesChannelCode: payload.salesChannelCode,
    });
    return ResponseUtil.success(
      quotes,
      'Shipping quotes returned successfully',
    );
  }
}
