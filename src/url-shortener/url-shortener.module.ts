// src/url-shortener/url-shortener.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { LoggerService } from '../utils/logger/logger.service';
import { DatabaseModule } from '../database/database.module';
import { UrlShortenerController } from './url-shortener.controller';
import { UrlShortenerService } from './url-shortener.service';

@Module({
  imports: [
    ConfigModule,
    DatabaseModule,
  ],
  controllers: [
    UrlShortenerController,
  ],
  providers: [
    UrlShortenerService,
    LoggerService,
  ],
  exports: [
    UrlShortenerService,
  ],
})
export class UrlShortenerModule {}