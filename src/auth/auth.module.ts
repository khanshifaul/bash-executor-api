// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { LoggerService } from 'src/utils/logger/logger.service';
import { DatabaseModule } from '../database/database.module';
import { MailModule } from '../mail/mail.module';
import { UsersModule } from '../users/users.module';

// New specialized controllers
import { ApiKeyController } from './controllers/api-key.controller';
import { AuthController } from './controllers/auth.controller';
import { SessionController } from './controllers/session.controller';

import { ApiKeyService } from './services/api-key.service';
import { AuthCoreService } from './services/auth-core.service';
import { SessionService } from './services/session.service';
import { TokenService } from './services/token.service';

// OAuth strategies

import { ApiKeyStrategy } from './strategies/api-key.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { RefreshTokenStrategy } from './strategies/refresh-token.strategy';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => {
        // Get JWT configuration from ConfigService
        const secret = configService.get<string>('JWT_SECRET');

        if (!secret) {
          throw new Error(
            'JWT_SECRET is not configured. Please check your .env file and ensure JWT_SECRET is set.',
          );
        }

        if (secret.length < 32) {
          throw new Error('JWT_SECRET must be at least 32 characters long');
        }

        return {
          secret: Buffer.from(secret, 'utf8'),
          signOptions: {
            issuer: 'stargate-api',
            audience: 'stargate-client',
          },
          verifyOptions: {
            issuer: 'stargate-api',
            audience: 'stargate-client',
          },
        };
      },
      inject: [ConfigService],
    }),
    UsersModule,
    MailModule,
    DatabaseModule,
  ],
  controllers: [
    // New specialized controllers
    AuthController,
    SessionController,
    ApiKeyController,

    // Original monolithic controller (for backward compatibility during transition)
    // OriginalAuthController,
  ],
  providers: [
    // New specialized services
    AuthCoreService,

    SessionService,
    TokenService,
    ApiKeyService,

    // Logger service
    LoggerService,

    // OAuth strategies
    LocalStrategy,
    JwtStrategy,
    RefreshTokenStrategy,
    ApiKeyStrategy,
  ],
  exports: [
    // Export new services for use in other modules
    AuthCoreService,
    SessionService,
    TokenService,

    // Export JWT and Passport modules
    JwtModule,
    PassportModule,
  ],
})
export class AuthModule {}
