import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { UrlShortenerModule } from '../url-shortener/url-shortener.module';

@Module({
  imports: [UrlShortenerModule],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}
