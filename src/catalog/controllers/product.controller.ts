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
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { ProductService } from '../services/product.service';
import { CreateProductDto, ProductStatus, ProductType } from '../dto/create-product.dto';
import { UpdateProductDto } from '../dto/update-product.dto';
import { FilterProductDto } from '../dto/filter-product.dto';

@Controller('catalog/products')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))
@UseGuards(JwtAuthGuard, PermissionsGuard)
@ApiTags('Catalog: Products')
@ApiBearerAuth('access-token')
export class ProductController {
  constructor(private readonly productService: ProductService) {}

  @Post()
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'create' })
  @ApiOperation({ summary: 'Create product with translations and variants' })
  @ApiCreatedResponse({ description: 'Product created successfully' })
  async create(@Body() payload: CreateProductDto) {
    const product = await this.productService.create(payload);
    return ResponseUtil.created(product, 'Product created successfully');
  }

  @Get()
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'read' })
  @ApiOperation({ summary: 'List products with pagination' })
  @ApiQuery({ name: 'page', required: false, type: Number, description: 'Page number (default 1)' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Page size (default 10)' })
  @ApiQuery({ name: 'status', required: false, enum: ProductStatus })
  @ApiQuery({ name: 'type', required: false, enum: ProductType })
  @ApiQuery({ name: 'isFeatured', required: false, type: Boolean })
  @ApiQuery({ name: 'search', required: false, type: String })
  @ApiOkResponse({ description: 'Products retrieved successfully' })
  async findAll(@Query() filters: FilterProductDto) {
    const result = await this.productService.findAll(filters);
    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Products retrieved successfully',
    );
  }

  @Get('/:id')
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'read' })
  @ApiOperation({ summary: 'Get product by id' })
  @ApiOkResponse({ description: 'Product retrieved successfully' })
  async findOne(@Param('id') id: string) {
    const product = await this.productService.findOne(id);
    return ResponseUtil.success(product, 'Product retrieved successfully');
  }

  @Patch('/:id')
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'update' })
  @ApiOperation({ summary: 'Update product and related data' })
  @ApiOkResponse({ description: 'Product updated successfully' })
  async update(@Param('id') id: string, @Body() payload: UpdateProductDto) {
    const product = await this.productService.update(id, payload);
    return ResponseUtil.updated(product, 'Product updated successfully');
  }

  @Delete('/:id')
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'delete' })
  @ApiOperation({ summary: 'Delete product' })
  @ApiOkResponse({ description: 'Product deleted successfully' })
  async remove(@Param('id') id: string) {
    await this.productService.remove(id);
    return ResponseUtil.deleted('Product deleted successfully');
  }
}
