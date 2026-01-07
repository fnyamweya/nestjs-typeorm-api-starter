import {
  Controller,
  Get,
  Param,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { ResponseUtil } from 'src/common/utils/response.util';
import { TaxonomyService } from '../../services/taxonomy.service';

@Controller('public/catalog/taxonomies')
@ApiTags('Public Catalog: Taxonomies')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
export class PublicTaxonomiesController {
  constructor(private readonly taxonomyService: TaxonomyService) {}

  @Get()
  @ApiOkResponse({ description: 'Public taxonomies retrieved successfully' })
  async list() {
    const rows = await this.taxonomyService.findAllPublic();
    return ResponseUtil.success(
      rows,
      'Public taxonomies retrieved successfully',
    );
  }

  @Get(':id')
  @ApiOkResponse({ description: 'Public taxonomy retrieved successfully' })
  async get(@Param('id') id: string) {
    const row = await this.taxonomyService.findOnePublic(id);
    return ResponseUtil.success(row, 'Public taxonomy retrieved successfully');
  }
}
