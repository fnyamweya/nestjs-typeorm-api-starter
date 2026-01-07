import {
  Body,
  BadRequestException,
  Controller,
  Delete,
  Get,
  Param,
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
import { CustomerAddressService } from '../services/customer-address.service';
import {
  CUSTOMER_ADDRESS_TYPES,
  CustomerAddressType,
} from '../customer-address.types';
import { UpsertAddressDto } from 'src/address/dto/upsert-address.dto';

@Controller('customer/addresses')
@UseGuards(JwtAuthGuard)
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@ApiTags('Customer Addresses')
@ApiBearerAuth('access-token')
export class CustomerAddressController {
  constructor(
    private readonly customerAddressService: CustomerAddressService,
  ) {}

  @Get()
  @ApiOkResponse({ description: 'Customer addresses retrieved' })
  async list(@CurrentUser() user: AuthenticatedUser) {
    const rows = await this.customerAddressService.listForUser(user.id);
    return ResponseUtil.success(rows, 'Customer addresses retrieved');
  }

  @Get(':type')
  @ApiOkResponse({ description: 'Customer address retrieved' })
  async getByType(
    @CurrentUser() user: AuthenticatedUser,
    @Param('type') type: CustomerAddressType,
  ) {
    const row = await this.customerAddressService.getForUserByType(
      user.id,
      type,
    );
    return ResponseUtil.success(row, 'Customer address retrieved');
  }

  @Put(':type')
  @ApiOkResponse({ description: 'Customer address saved' })
  async upsert(
    @CurrentUser() user: AuthenticatedUser,
    @Param('type') type: CustomerAddressType,
    @Body() payload: UpsertAddressDto,
  ) {
    // ensure only 3 types are allowed
    if (!CUSTOMER_ADDRESS_TYPES.includes(type)) {
      throw new BadRequestException('Invalid address type');
    }

    const row = await this.customerAddressService.upsertForUser(
      user.id,
      type,
      payload,
    );
    return ResponseUtil.success(row, 'Customer address saved');
  }

  @Delete(':type')
  @ApiOkResponse({ description: 'Customer address deleted' })
  async deleteByType(
    @CurrentUser() user: AuthenticatedUser,
    @Param('type') type: CustomerAddressType,
  ) {
    const result = await this.customerAddressService.deleteForUserByType(
      user.id,
      type,
    );
    return ResponseUtil.success(result, 'Customer address deleted');
  }
}
