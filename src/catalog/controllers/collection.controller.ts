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
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { CollectionService } from '../services/collection.service';
import {
  CreateCollectionDto,
  FilterCollectionDto,
  UpdateCollectionDto,
  UpdateCollectionItemsDto,
} from '../dto/collection.dto';

@Controller('catalog/collections')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
@ApiTags('Catalog: Collections')
export class CollectionController {
  constructor(private readonly collectionService: CollectionService) {}

  @Post()
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({ module: PermissionModule.CATALOG, permission: 'create' })
  @ApiOperation({ summary: 'Create a collection' })
  @ApiCreatedResponse({ description: 'Collection created successfully' })
  async create(@Body() payload: CreateCollectionDto) {
    const collection = await this.collectionService.create(payload);
    return ResponseUtil.created(collection, 'Collection created successfully');
  }

  @Get()
  @ApiOperation({ summary: 'List collections with pagination' })
  @ApiOkResponse({ description: 'Collections retrieved successfully' })
  async findAll(@Query() filters: FilterCollectionDto) {
    const result = await this.collectionService.findAll(filters);
    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Collections retrieved successfully',
    );
  }

  @Get('/:id')
  @ApiOperation({ summary: 'Get collection by id' })
  @ApiOkResponse({ description: 'Collection retrieved successfully' })
  async findOne(@Param('id') id: string) {
    const collection = await this.collectionService.findOne(id);
    return ResponseUtil.success(collection, 'Collection retrieved successfully');
  }

  @Patch('/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({ module: PermissionModule.CATALOG, permission: 'update' })
  @ApiOperation({ summary: 'Update collection' })
  @ApiOkResponse({ description: 'Collection updated successfully' })
  async update(@Param('id') id: string, @Body() payload: UpdateCollectionDto) {
    const collection = await this.collectionService.update(id, payload);
    return ResponseUtil.updated(collection, 'Collection updated successfully');
  }

  @Post('/:id/items')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({ module: PermissionModule.CATALOG, permission: 'update' })
  @ApiOperation({ summary: 'Replace items for a static collection' })
  @ApiOkResponse({ description: 'Collection items updated successfully' })
  async replaceItems(
    @Param('id') id: string,
    @Body() payload: UpdateCollectionItemsDto,
  ) {
    const collection = await this.collectionService.replaceItems(id, payload);
    return ResponseUtil.updated(
      collection,
      'Collection items updated successfully',
    );
  }

  @Delete('/:id')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @ApiBearerAuth('access-token')
  @RequirePermissions({ module: PermissionModule.CATALOG, permission: 'delete' })
  @ApiOperation({ summary: 'Delete collection' })
  @ApiOkResponse({ description: 'Collection deleted successfully' })
  async remove(@Param('id') id: string) {
    await this.collectionService.remove(id);
    return ResponseUtil.deleted('Collection deleted successfully');
  }
}
