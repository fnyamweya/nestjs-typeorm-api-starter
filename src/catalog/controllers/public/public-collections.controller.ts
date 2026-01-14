import { Controller, Get, Param, Query, UsePipes, ValidationPipe } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { ResponseUtil } from 'src/common/utils/response.util';
import { PublicCollectionsQueryDto } from '../../dto/collection.dto';
import { CollectionService } from '../../services/collection.service';

@Controller('public/catalog/collections')
@ApiTags('Public Catalog: Collections')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
export class PublicCollectionsController {
  constructor(private readonly collectionService: CollectionService) {}

  @Get()
  @ApiOperation({ summary: 'Get multiple collections by slug' })
  @ApiOkResponse({ description: 'Collections retrieved successfully' })
  async list(@Query() query: PublicCollectionsQueryDto) {
    const slugs = query.slugs
      ?.split(',')
      .map((slug) => slug.trim())
      .filter(Boolean);

    if (!slugs?.length) {
      return ResponseUtil.success([], 'No collection slugs provided');
    }

    const collections = await this.collectionService.getPublicCollections(
      slugs,
      query.limit,
    );
    return ResponseUtil.success(collections, 'Collections retrieved successfully');
  }

  @Get('/:slug')
  @ApiOperation({ summary: 'Get a single collection by slug' })
  @ApiOkResponse({ description: 'Collection retrieved successfully' })
  async getOne(
    @Param('slug') slug: string,
    @Query() query: PublicCollectionsQueryDto,
  ) {
    const collection = await this.collectionService.getPublicCollection(
      slug,
      query.limit,
    );
    return ResponseUtil.success(collection, 'Collection retrieved successfully');
  }
}
