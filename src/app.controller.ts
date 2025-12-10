import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { AppService } from './app.service';

@Controller()
@ApiTags('App')
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @ApiOperation({ summary: 'Simple health check endpoint' })
  @ApiOkResponse({ description: 'Returns a friendly greeting' })
  getHello(): string {
    return this.appService.getHello();
  }
}
