
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ScheduleModule } from '@nestjs/schedule';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { join } from 'path';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { AccessTokenGuard } from './common/guards/access-token.guard';
import { RoleGuard } from './common/guards/role.guard';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';
import { CsrfMiddleware } from './common/middleware/csrf.middleware';
import { UrlConfigService } from './config/url.config';
import { validationSchema } from './config/validation.schema';
import { DatabaseModule } from './database/database.module';
import { MailModule } from './mail/mail.module';
import { RunnerModule } from './runner/runner.module';
import { UrlShortenerModule } from './url-shortener/url-shortener.module';
import { UsersModule } from './users/users.module';
import { LoggerService } from './utils/logger/logger.service';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [() => require('./config/app.config').appConfig()],
      validationSchema,
      envFilePath: ['.env.local', '.env'],
    }),
    ScheduleModule.forRoot(),
    {
      module: class { },
      providers: [UrlConfigService],
      exports: [UrlConfigService],
      global: true,
    },
    // FIX: Corrected ThrottlerModule configuration - must use 'throttlers' array
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        throttlers: [
          {
            ttl: config.get<number>('THROTTLE_TTL', 60000),
            limit: config.get<number>('THROTTLE_LIMIT', 100),
          },
        ],
      }),
    }),
    EventEmitterModule.forRoot({
      wildcard: false,
      delimiter: '.',
      newListener: false,
      removeListener: false,
      maxListeners: 10,
      verboseMemoryLeak: false,
      ignoreErrors: false,
    }),
    DatabaseModule,
    AuthModule,
    UsersModule,
    UrlShortenerModule,
    MailModule,
    RunnerModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    LoggerService,
    {
      provide: APP_INTERCEPTOR,
      useClass: ResponseInterceptor,
    },
    {
      provide: APP_GUARD,
      useClass: AccessTokenGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RoleGuard,
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    CsrfMiddleware,
  ],
})
export class AppModule { }
