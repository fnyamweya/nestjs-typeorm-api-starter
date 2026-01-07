import {
  Controller,
  Get,
  Param,
  Query,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { ResponseUtil } from 'src/common/utils/response.util';
import { BrandService } from '../../services/brand.service';
import { PublicListBrandsDto } from '../../dto/public/public-list-brands.dto';

@Controller('public/catalog/brands')
@ApiTags('Public Catalog: Brands')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
export class PublicBrandsController {
  constructor(private readonly brandService: BrandService) {}

  @Get()
  @ApiOkResponse({ description: 'Public brands retrieved successfully' })
  async list(@Query() query: PublicListBrandsDto) {
    const result = await this.brandService.findAllPublic(query);
    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Public brands retrieved successfully',
    );
  }

  @Get(':id')
  @ApiOkResponse({ description: 'Public brand retrieved successfully' })
  async get(@Param('id') id: string) {
    const brand = await this.brandService.findOnePublic(id);
    return ResponseUtil.success(brand, 'Public brand retrieved successfully');
  }
}
