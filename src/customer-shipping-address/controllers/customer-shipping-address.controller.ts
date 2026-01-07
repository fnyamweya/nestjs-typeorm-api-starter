import {
  Body,
  Controller,
  Get,
  Put,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { AuthenticatedUser } from 'src/auth/interfaces/user.interface';
import { ResponseUtil } from 'src/common/utils/response.util';
import { UpsertAddressDto } from 'src/address/dto/upsert-address.dto';
import { CustomerShippingAddressService } from '../services/customer-shipping-address.service';

@Controller('customer/shipping-address')
@UseGuards(JwtAuthGuard)
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@ApiTags('Customer Shipping Address')
@ApiBearerAuth('access-token')
export class CustomerShippingAddressController {
  constructor(
    private readonly customerShippingAddressService: CustomerShippingAddressService,
  ) {}

  @Get()
  @ApiOkResponse({ description: 'Customer shipping address retrieved' })
  async get(@CurrentUser() user: AuthenticatedUser) {
    const row = await this.customerShippingAddressService.getForUser(user.id);
    return ResponseUtil.success(row, 'Customer shipping address retrieved');
  }

  @Put()
  @ApiOkResponse({ description: 'Customer shipping address saved' })
  async upsert(
    @CurrentUser() user: AuthenticatedUser,
    @Body() payload: UpsertAddressDto,
  ) {
    const row = await this.customerShippingAddressService.upsertForUser(
      user.id,
      payload,
    );
    return ResponseUtil.success(row, 'Customer shipping address saved');
  }
}
