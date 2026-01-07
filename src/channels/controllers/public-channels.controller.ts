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
import { PublicListChannelsDto } from '../dto/public-list-channels.dto';
import { ChannelsService } from '../services/channels.service';

@Controller('public/channels')
@ApiTags('Public Channels')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
)
export class PublicChannelsController {
  constructor(private readonly channelsService: ChannelsService) {}

  @Get()
  @ApiOkResponse({ description: 'Public channels retrieved' })
  async list(@Query() query: PublicListChannelsDto) {
    const rows = await this.channelsService.listPublic(query);
    return ResponseUtil.success(rows, 'Public channels retrieved');
  }

  @Get(':code')
  @ApiOkResponse({ description: 'Public channel retrieved' })
  async getByCode(@Param('code') code: string) {
    const row = await this.channelsService.getPublicByCode(code);
    return ResponseUtil.success(row, 'Public channel retrieved');
  }
}
