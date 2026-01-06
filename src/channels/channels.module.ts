import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Channel } from './entities/channel.entity';
import { ChannelsService } from './services/channels.service';
import { ChannelsController } from './controllers/channels.controller';
import { PublicChannelsController } from './controllers/public-channels.controller';
import { ChannelsSeeder } from './seeders/channels.seeder';
import { CurrencyModule } from 'src/currency/currency.module';

@Module({
  imports: [TypeOrmModule.forFeature([Channel]), CurrencyModule],
  providers: [ChannelsService, ChannelsSeeder],
  controllers: [ChannelsController, PublicChannelsController],
  exports: [ChannelsService, ChannelsSeeder, TypeOrmModule],
})
export class ChannelsModule {}
