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
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { CreatePriceListDto } from './dto/create-price-list.dto';
import { FilterPriceListDto } from './dto/filter-price-list.dto';
import { UpdatePriceListDto } from './dto/update-price-list.dto';
import { PricingService } from './pricing.service';

@Controller('pricing/price-lists')
@ApiTags('Pricing')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
export class PricingController {
  constructor(private readonly pricingService: PricingService) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.PRICING,
    permission: 'create',
  })
  @ApiOperation({ summary: 'Create a price list' })
  @ApiCreatedResponse({ description: 'Price list created' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to create price lists',
  })
  async create(@Body() payload: CreatePriceListDto) {
    const row = await this.pricingService.createPriceList(payload);
    return ResponseUtil.created(row, 'Price list created');
  }

  @Get()
  @RequirePermissions({ module: PermissionModule.PRICING, permission: 'read' })
  @ApiOperation({ summary: 'List price lists' })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'getAll', required: false, type: Boolean })
  @ApiQuery({ name: 'search', required: false, type: String })
  @ApiQuery({ name: 'currency', required: false, type: String, example: 'KES' })
  @ApiQuery({
    name: 'status',
    required: false,
    type: String,
    example: 'active',
  })
  @ApiOkResponse({ description: 'Price lists retrieved' })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid authentication token',
  })
  @ApiForbiddenResponse({
    description: 'Insufficient permissions to read price lists',
  })
  async list(@Query() filters: FilterPriceListDto) {
    const result = await this.pricingService.listPriceLists(filters);

    if (filters.getAll) {
      return ResponseUtil.success(result.data, 'All price lists retrieved');
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Price lists retrieved',
    );
  }

  @Get(':id')
  @RequirePermissions({ module: PermissionModule.PRICING, permission: 'read' })
  @ApiOperation({ summary: 'Get a price list by id' })
  @ApiParam({ name: 'id', description: 'Price list UUID' })
  @ApiOkResponse({ description: 'Price list retrieved' })
  async get(@Param('id') id: string) {
    const row = await this.pricingService.getPriceList(id);
    return ResponseUtil.success(row, 'Price list retrieved');
  }

  @Patch(':id')
  @RequirePermissions({
    module: PermissionModule.PRICING,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Update a price list' })
  @ApiParam({ name: 'id', description: 'Price list UUID' })
  @ApiOkResponse({ description: 'Price list updated' })
  async update(@Param('id') id: string, @Body() payload: UpdatePriceListDto) {
    const row = await this.pricingService.updatePriceList(id, payload);
    return ResponseUtil.success(row, 'Price list updated');
  }

  @Delete(':id')
  @RequirePermissions({
    module: PermissionModule.PRICING,
    permission: 'delete',
  })
  @ApiOperation({ summary: 'Delete a price list' })
  @ApiParam({ name: 'id', description: 'Price list UUID' })
  @ApiOkResponse({ description: 'Price list deleted' })
  async remove(@Param('id') id: string) {
    const res = await this.pricingService.deletePriceList(id);
    return ResponseUtil.success(res, 'Price list deleted');
  }
}
