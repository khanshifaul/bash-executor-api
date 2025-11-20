// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { LoggerService } from 'src/utils/logger/logger.service';
import { MailModule } from '../mail/mail.module';
import { UsersModule } from '../users/users.module';
import { DatabaseModule } from '../database/database.module';

// New specialized controllers
import { AuthController } from './controllers/auth.controller';
import { OAuthController } from './controllers/oauth.controller';
import { SessionController } from './controllers/session.controller';
import { TwoFactorController } from './controllers/two-factor.controller';
import { ApiKeyController } from './controllers/api-key.controller';

import { AuthCoreService } from './services/auth-core.service';
import { OAuthService } from './services/oauth.service';
import { SessionService } from './services/session.service';
import { TokenService } from './services/token.service';
import { TwoFactorService } from './services/two-factor.service';
import { ApiKeyService } from './services/api-key.service';

// OAuth strategies

import { GithubStrategy } from './strategies/github.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { RefreshTokenStrategy } from './strategies/refresh-token.strategy';
import { ApiKeyStrategy } from './strategies/api-key.strategy';

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
    OAuthController,
    TwoFactorController,
    SessionController,
    ApiKeyController,

    // Original monolithic controller (for backward compatibility during transition)
    // OriginalAuthController,
  ],
  providers: [
    // New specialized services
    AuthCoreService,
    OAuthService,
    TwoFactorService,
    SessionService,
    TokenService,
    ApiKeyService,

    // Logger service
    LoggerService,

    // OAuth strategies
    LocalStrategy,
    JwtStrategy,
    RefreshTokenStrategy,
    GoogleStrategy,
    GithubStrategy,
    ApiKeyStrategy,
  ],
  exports: [
    // Export new services for use in other modules
    AuthCoreService,
    OAuthService,
    TwoFactorService,
    SessionService,
    TokenService,

    // Export JWT and Passport modules
    JwtModule,
    PassportModule,
  ],
})
export class AuthModule { }
