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
  ApiBody,
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
import { CreateProductDto, ProductStatus } from '../dto/create-product.dto';
import { UpdateProductDto } from '../dto/update-product.dto';
import { FilterProductDto } from '../dto/filter-product.dto';
import { CreateProductPriceDto } from '../dto/create-product-price.dto';
import { CreateProductContextOverrideDto } from '../dto/product-v2/create-product-context-override.dto';
import { UpdateProductContextOverrideDto } from '../dto/product-v2/update-product-context-override.dto';

@Controller('catalog/products')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@ApiTags('Catalog: Products')
export class ProductController {
  constructor(private readonly productService: ProductService) {}

  @Post()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({
    module: PermissionModule.PRODUCTS,
    permission: 'create',
  })
  @ApiOperation({ summary: 'Create product' })
  @ApiBody({
    description: 'Product payload (SKU-level availability/images/pricing)',
    schema: {
      type: 'object',
      properties: {
        title: { type: 'string', example: 'iPhone 15' },
        description: { type: 'string', example: 'Flagship smartphone' },
        seoTitle: { type: 'string', example: 'iPhone 15 | Shop' },
        seoDescription: {
          type: 'string',
          example: 'Flagship smartphone with pro-grade camera and long battery life.',
        },
        status: { type: 'string', example: 'draft' },
        externalRef: { type: 'string', example: 'erp-1234' },
        brandId: { type: 'string', format: 'uuid' },
        categoryIds: { type: 'array', items: { type: 'string', format: 'uuid' } },
        optionDefinitions: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              key: { type: 'string', example: 'color' },
              label: { type: 'string', example: 'Color' },
              allowedValues: {
                type: 'array',
                items: { type: 'string', example: 'black' },
              },
              required: { type: 'boolean', example: false },
            },
          },
        },
        skus: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              title: { type: 'string', example: 'Black / 128 GB' },
              sku: { type: 'string', example: 'IPH-15-BLK-128' },
              externalRef: { type: 'string', example: 'shopify-sku-123' },
              status: { type: 'string', example: 'active' },
              isDefault: { type: 'boolean', example: true },
              position: { type: 'number', example: 1 },
              attributes: {
                type: 'object',
                example: { color: 'black', size: 'M' },
              },
              options: {
                type: 'object',
                example: { color: 'black', size: 'M' },
              },
              availability: {
                type: 'object',
                example: {
                  channels: ['WEB', 'APP'],
                  countries: ['KE'],
                  locations: ['Baringo', 'Dagoretti North'],
                  stock: { type: 'FINITE', quantity: 20 },
                  schedule: {
                    startAt: '2025-01-01T00:00:00Z',
                    endAt: '2025-12-31T23:59:59Z',
                    timezone: 'UTC',
                  },
                  meta: {},
                },
              },
              inventory: {
                type: 'object',
                example: { locations: { NAIROBI: { onHand: 10, reserved: 2 } } },
              },
              images: {
                type: 'array',
                items: { type: 'string', example: 'https://cdn.example.com/1.png' },
              },
              requiresShipping: { type: 'boolean', example: true },
              weight: { type: 'number', example: 0.2 },
              length: { type: 'number', example: 10.5 },
              width: { type: 'number', example: 5.25 },
              height: { type: 'number', example: 2.75 },
              dimensionUnit: { type: 'string', example: 'cm' },
              weightUnit: { type: 'string', example: 'kg' },
              metaJson: { type: 'object', example: { preorder: true } },
              prices: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    priceListId: { type: 'string', format: 'uuid' },
                    unitPrice: { type: 'number', example: 1999.99 },
                    compareAtPrice: { type: 'number', example: 2499.99 },
                    minQuantity: { type: 'number', example: 1 },
                    maxQuantity: { type: 'number', example: 10 },
                    validFrom: { type: 'string', example: '2025-01-01T00:00:00Z' },
                    validTo: { type: 'string', example: '2025-02-01T00:00:00Z' },
                    metaJson: { type: 'object', example: { reason: 'promo' } },
                  },
                },
              },
            },
          },
        },
        metaJson: { type: 'object', example: {} },
      },
      required: ['title'],
    },
  })
  @ApiCreatedResponse({ description: 'Product created successfully' })
  async create(@Body() payload: CreateProductDto) {
    const product = await this.productService.create(payload);
    return ResponseUtil.created(product, 'Product created successfully');
  }

  @Get()
  @ApiOperation({ summary: 'List products with pagination' })
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
  @ApiQuery({ name: 'status', required: false, enum: ProductStatus })
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
  @ApiOperation({ summary: 'Get product by id' })
  @ApiOkResponse({ description: 'Product retrieved successfully' })
  async findOne(@Param('id') id: string) {
    const product = await this.productService.findOne(id);
    return ResponseUtil.success(product, 'Product retrieved successfully');
  }

  @Patch('/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({
    module: PermissionModule.PRODUCTS,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Update product' })
  @ApiOkResponse({ description: 'Product updated successfully' })
  async update(@Param('id') id: string, @Body() payload: UpdateProductDto) {
    const product = await this.productService.update(id, payload);
    return ResponseUtil.updated(product, 'Product updated successfully');
  }

  @Delete('/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({
    module: PermissionModule.PRODUCTS,
    permission: 'delete',
  })
  @ApiOperation({ summary: 'Delete product' })
  @ApiOkResponse({ description: 'Product deleted successfully' })
  async remove(@Param('id') id: string) {
    await this.productService.remove(id);
    return ResponseUtil.deleted('Product deleted successfully');
  }

  @Post('/:id/prices')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({
    module: PermissionModule.PRODUCTS,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Add product-level price' })
  @ApiCreatedResponse({ description: 'Product price created successfully' })
  async addProductPrice(
    @Param('id') id: string,
    @Body() payload: CreateProductPriceDto,
  ) {
    const price = await this.productService.addProductPrice(id, payload);
    return ResponseUtil.created(price, 'Product price created successfully');
  }

  @Get('/:id/prices')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'read' })
  @ApiOperation({ summary: 'List product-level prices' })
  @ApiOkResponse({ description: 'Product prices retrieved successfully' })
  async listProductPrices(@Param('id') id: string) {
    const prices = await this.productService.listProductPrices(id);
    return ResponseUtil.success(
      prices,
      'Product prices retrieved successfully',
    );
  }

  @Post('/:id/skus/:skuId/prices')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({
    module: PermissionModule.PRODUCTS,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Add SKU price' })
  @ApiCreatedResponse({ description: 'SKU price created successfully' })
  async addSkuPrice(
    @Param('id') id: string,
    @Param('skuId') skuId: string,
    @Body() payload: CreateProductPriceDto,
  ) {
    const price = await this.productService.addSkuPrice(id, skuId, payload);
    return ResponseUtil.created(price, 'SKU price created successfully');
  }

  @Get('/:id/skus/:skuId/prices')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'read' })
  @ApiOperation({ summary: 'List SKU prices' })
  @ApiOkResponse({ description: 'SKU prices retrieved successfully' })
  async listSkuPrices(@Param('id') id: string, @Param('skuId') skuId: string) {
    const prices = await this.productService.listSkuPrices(id, skuId);
    return ResponseUtil.success(prices, 'SKU prices retrieved successfully');
  }

  @Get('/:id/overrides')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({ module: PermissionModule.PRODUCTS, permission: 'read' })
  @ApiOperation({ summary: 'List product context overrides' })
  @ApiOkResponse({
    description: 'Product context overrides retrieved successfully',
  })
  async listContextOverrides(@Param('id') id: string) {
    const overrides = await this.productService.listContextOverrides(id);
    return ResponseUtil.success(
      overrides,
      'Product context overrides retrieved successfully',
    );
  }

  @Post('/:id/overrides')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({
    module: PermissionModule.PRODUCTS,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Create product context override' })
  @ApiCreatedResponse({
    description: 'Product context override created successfully',
  })
  async createContextOverride(
    @Param('id') id: string,
    @Body() payload: CreateProductContextOverrideDto,
  ) {
    const override = await this.productService.createContextOverride(
      id,
      payload,
    );
    return ResponseUtil.created(
      override,
      'Product context override created successfully',
    );
  }

  @Patch('/:id/overrides/:overrideId')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({
    module: PermissionModule.PRODUCTS,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Update product context override' })
  @ApiOkResponse({
    description: 'Product context override updated successfully',
  })
  async updateContextOverride(
    @Param('id') id: string,
    @Param('overrideId') overrideId: string,
    @Body() payload: UpdateProductContextOverrideDto,
  ) {
    const override = await this.productService.updateContextOverride(
      id,
      overrideId,
      payload,
    );
    return ResponseUtil.updated(
      override,
      'Product context override updated successfully',
    );
  }

  @Delete('/:id/overrides/:overrideId')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({
    module: PermissionModule.PRODUCTS,
    permission: 'update',
  })
  @ApiOperation({ summary: 'Delete product context override' })
  @ApiOkResponse({
    description: 'Product context override deleted successfully',
  })
  async removeContextOverride(
    @Param('id') id: string,
    @Param('overrideId') overrideId: string,
  ) {
    await this.productService.removeContextOverride(id, overrideId);
    return ResponseUtil.deleted(
      'Product context override deleted successfully',
    );
  }
}
