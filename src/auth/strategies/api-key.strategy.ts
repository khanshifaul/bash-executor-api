// src/auth/strategies/api-key.strategy.ts
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { HeaderAPIKeyStrategy } from 'passport-headerapikey';
import { PrismaService } from '../../database/prisma/prisma.service';
import { LoggerService } from '../../utils/logger/logger.service';

export interface ApiKeyPayload {
  key: string;
  userId: string;
  permissions: string[];
  scopes: string[];
  isActive: boolean;
  expiresAt?: Date;
  usageLimit?: number;
  usageCount: number;
}

@Injectable()
export class ApiKeyStrategy extends PassportStrategy(
  HeaderAPIKeyStrategy,
  'api-key',
) {
  private readonly logger = new Logger(ApiKeyStrategy.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly loggerService: LoggerService,
  ) {
    super({ header: 'X-API-Key', prefix: '' }, false);
  }

  async validate(apiKey: string, done: Function) {
    try {
      return await this.validateApiKey(apiKey, done);
    } catch (error) {
      this.logger.error(`API key validation failed:`, error.message);
      return done(error, false);
    }
  }

  private async validateApiKey(apiKey: string, done: Function) {
    try {
      // Find the API key in the database
      const apiKeyRecord = await this.prisma.apiKey.findUnique({
        where: { key: apiKey },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true,
              status: true,
              role: true,
            },
          },
        },
      });

      if (!apiKeyRecord) {
        this.loggerService.security('API_KEY_NOT_FOUND', { apiKey }, undefined);
        throw new UnauthorizedException('Invalid API key');
      }

      // Check if the API key is active
      if (!apiKeyRecord.isActive) {
        this.loggerService.security(
          'API_KEY_INACTIVE',
          { apiKeyId: apiKeyRecord.id },
          apiKeyRecord.userId,
        );
        throw new UnauthorizedException('API key is inactive');
      }

      // Check if the user is active
      if (apiKeyRecord.user.status !== 'ACTIVE') {
        this.loggerService.security(
          'USER_INACTIVE_FOR_API_KEY',
          { apiKeyId: apiKeyRecord.id },
          apiKeyRecord.userId,
        );
        throw new UnauthorizedException('User account is inactive');
      }

      // Check if the API key has expired
      if (apiKeyRecord.expiresAt && apiKeyRecord.expiresAt < new Date()) {
        this.loggerService.security(
          'API_KEY_EXPIRED',
          { apiKeyId: apiKeyRecord.id },
          apiKeyRecord.userId,
        );
        throw new UnauthorizedException('API key has expired');
      }

      // Check usage limit
      if (
        apiKeyRecord.usageLimit &&
        apiKeyRecord.usageCount >= apiKeyRecord.usageLimit
      ) {
        this.loggerService.security(
          'API_KEY_USAGE_LIMIT_EXCEEDED',
          { apiKeyId: apiKeyRecord.id },
          apiKeyRecord.userId,
        );
        throw new UnauthorizedException('API key usage limit exceeded');
      }

      // Update usage statistics
      await this.prisma.apiKey.update({
        where: { id: apiKeyRecord.id },
        data: {
          usageCount: { increment: 1 },
          lastUsedAt: new Date(),
        },
      });

      // Create the payload
      const payload: ApiKeyPayload = {
        key: apiKey,
        userId: apiKeyRecord.userId,
        permissions: apiKeyRecord.permissions,
        scopes: apiKeyRecord.scopes,
        isActive: apiKeyRecord.isActive,
        expiresAt: apiKeyRecord.expiresAt || undefined,
        usageLimit: apiKeyRecord.usageLimit || undefined,
        usageCount: apiKeyRecord.usageCount + 1,
      };

      this.loggerService.security(
        'API_KEY_VALIDATED',
        { apiKeyId: apiKeyRecord.id },
        apiKeyRecord.userId,
      );

      return done(
        null,
        {
          ...apiKeyRecord.user,
          apiKeyId: apiKeyRecord.id,
          apiKeyName: apiKeyRecord.name,
          permissions: apiKeyRecord.permissions,
          scopes: apiKeyRecord.scopes,
          type: 'api-key',
        },
        payload,
      );
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      this.logger.error('API key validation error:', error.message);
      throw new UnauthorizedException('API key validation failed');
    }
  }
}
