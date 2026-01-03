import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { GooglePlacesService } from './google-places.service';

@Module({
  imports: [HttpModule],
  providers: [GooglePlacesService],
  exports: [GooglePlacesService],
})
export class GooglePlacesModule {}
