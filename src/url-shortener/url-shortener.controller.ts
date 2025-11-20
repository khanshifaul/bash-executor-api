import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse as ApiResponseDecorator,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { Public } from 'src/common/decorators/public.decorator';
import { User } from 'src/common/decorators/user.decorator';
import { AccessTokenGuard } from 'src/common/guards/access-token.guard';
import { UrlShortenerService, CreateShortUrlDto, AnalyticsData } from './url-shortener.service';
import { BaseController } from '../auth/base/base.controller';
import { ApiResponse } from '../auth/shared/interfaces/api-response.interface';

@ApiTags('URL Shortener')
@Controller()
export class UrlShortenerController extends BaseController {
  constructor(
    private readonly urlShortenerService: UrlShortenerService,
  ) {
    super();
  }

  // ========== REDIRECT ENDPOINT ==========
  @Public()
  @Get('s/:shortCode')
  @ApiOperation({
    summary: 'Redirect to original URL',
    description: 'Redirects to the original URL for a given short code',
  })
  @ApiResponseDecorator({
    status: 302,
    description: 'Redirect to original URL',
  })
  @ApiResponseDecorator({
    status: 404,
    description: 'Short URL not found or expired',
  })
  async redirectToOriginal(
    @Param('shortCode') shortCode: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    try {
      if (!shortCode) {
        throw new BadRequestException('Short code is required');
      }

      const originalUrl = await this.urlShortenerService.getOriginalUrl(shortCode);

      // Log the redirect for security and analytics
      this.logInfo(
        'redirectToOriginal',
        `Short URL redirect: ${shortCode} -> ${originalUrl}, IP: ${req.ip}`
      );

      // Perform the redirect
      return res.redirect(302, originalUrl);
    } catch (error) {
      if (error instanceof NotFoundException) {
        const errorResponse = this.createErrorResponse(
          'Short URL not found or has expired',
          'URL_NOT_FOUND',
          'INVALID_SHORT_CODE',
        );
        return res.status(404).json(errorResponse);
      }

      this.logger.error(
        'Short URL redirect failed',
        'UrlShortenerController',
        { error: error.message, shortCode, ip: req.ip }
      );

      const errorResponse = this.createErrorResponse(
        'Failed to process short URL',
        'REDIRECT_FAILED',
        'INTERNAL_ERROR',
      );
      return res.status(400).json(errorResponse);
    }
  }

  // ========== ANALYTICS ENDPOINT ==========
  @Get('url-shortener/analytics/:shortCode')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 30, ttl: 60000 } })
  @ApiOperation({
    summary: 'Get URL analytics',
    description: 'Returns analytics data for a short URL (click count, creation date, etc.)',
  })
  @ApiResponseDecorator({
    status: 200,
    description: 'Analytics data retrieved successfully',
    schema: {
      example: {
        success: true,
        message: 'Analytics data retrieved successfully',
        data: {
          shortCode: 'abc123',
          clickCount: 42,
          createdAt: '2024-01-15T10:30:00.000Z',
          expiresAt: '2024-01-22T10:30:00.000Z',
          isActive: true,
        },
      },
    },
  })
  @ApiResponseDecorator({
    status: 404,
    description: 'Short URL not found or not owned by user',
  })
  async getUrlAnalytics(
    @Param('shortCode') shortCode: string,
    @User('id') userId: string,
    @User('role') userRole: string,
  ): Promise<ApiResponse> {
    try {
      if (!shortCode) {
        throw new BadRequestException('Short code is required');
      }

      const analytics: AnalyticsData = await this.urlShortenerService.getAnalytics(
        shortCode,
        userId,
        userRole,
      );

      return this.createSuccessResponse(
        'Analytics data retrieved successfully',
        analytics,
      );
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error; // Keep not found errors as HttpExceptions
      }

      return this.handleServiceError(
        'getUrlAnalytics',
        error,
        'Failed to retrieve analytics data',
      );
    }
  }

  // ========== ADMIN LIST ALL ENDPOINT ==========
  @Get('url-shortener')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 30, ttl: 60000 } })
  @ApiOperation({
    summary: 'Get all shortened URLs (Admin)',
    description: 'Returns all shortened URLs with their original URLs and analytics (admin only)',
  })
  @ApiResponseDecorator({
    status: 200,
    description: 'All shortened URLs retrieved successfully',
    schema: {
      example: {
        success: true,
        message: 'All shortened URLs retrieved successfully',
        data: [
          {
            shortCode: 'abc123',
            originalUrl: 'https://example.com/very/long/url',
            userId: 'user-id',
            clickCount: 42,
            createdAt: '2024-01-15T10:30:00.000Z',
            expiresAt: '2024-01-22T10:30:00.000Z',
            isActive: true,
          },
        ],
      },
    },
  })
  @ApiResponseDecorator({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getAllShortenedUrls(
    @User('role') userRole: string,
  ): Promise<ApiResponse> {
    try {
      // Check admin role
      if (userRole !== 'ADMIN') {
        throw new ForbiddenException('Admin access required');
      }

      const allUrls = await this.urlShortenerService.getAllShortenedUrls();

      return this.createSuccessResponse(
        'All shortened URLs retrieved successfully',
        allUrls,
      );
    } catch (error) {
      if (error instanceof ForbiddenException) {
        throw error;
      }

      return this.handleServiceError(
        'getAllShortenedUrls',
        error,
        'Failed to retrieve shortened URLs',
      );
    }
  }

  // ========== INTERNAL CREATE ENDPOINT ==========
  @Post('url-shortener/create')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.CREATED)
  @Throttle({ default: { limit: 100, ttl: 60000 } })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['originalUrl'],
      properties: {
        originalUrl: {
          type: 'string',
          format: 'uri',
          example: 'https://example.com/very/long/url/that/needs/shortening',
          description: 'The original URL to be shortened'
        },
        expiresInHours: {
          type: 'number',
          minimum: 1,
          maximum: 8760, // 1 year
          example: 24,
          description: 'URL expiration time in hours (optional, defaults to 24h)'
        }
      }
    },
    examples: {
      basic: {
        value: {
          originalUrl: 'https://example.com/very/long/url/that/needs/shortening',
          expiresInHours: 24
        },
        summary: 'Basic usage with expiration'
      },
      noExpiry: {
        value: {
          originalUrl: 'https://example.com/permanent/link'
        },
        summary: 'URL without expiration'
      }
    }
  })
  @ApiOperation({
    summary: 'Create short URL',
    description: 'Creates a new shortened URL for internal use',
  })
  @ApiResponseDecorator({
    status: 201,
    description: 'Short URL created successfully',
    schema: {
      example: {
        success: true,
        message: 'Short URL created successfully',
        data: {
          shortCode: 'abc123',
          shortUrl: 'https://yourdomain.com/s/abc123',
          originalUrl: 'https://example.com/very/long/url',
          expiresAt: '2024-01-22T10:30:00.000Z',
          clickCount: 0,
        },
      },
    },
  })
  @ApiResponseDecorator({
    status: 400,
    description: 'Invalid URL format or creation failed',
  })
  async createShortUrl(
    @Body() createShortUrlDto: CreateShortUrlDto,
    @User('id') userId: string,
  ): Promise<ApiResponse> {
    try {
      if (!createShortUrlDto.originalUrl) {
        throw new BadRequestException('Original URL is required');
      }

      // Add user ID to the DTO
      const dtoWithUserId = {
        ...createShortUrlDto,
        userId,
      };

      const shortUrlData = await this.urlShortenerService.createShortUrl(dtoWithUserId);

      return this.createSuccessResponse(
        'Short URL created successfully',
        shortUrlData,
      );
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error; // Keep validation errors as HttpExceptions
      }

      return this.handleServiceError(
        'createShortUrl',
        error,
        'Failed to create short URL',
      );
    }
  }

  // ========== DEACTIVATE URL ENDPOINT ==========
  @Post('url-shortener/deactivate/:shortCode')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 50, ttl: 60000 } })
  @ApiOperation({
    summary: 'Deactivate short URL',
    description: 'Deactivates a short URL (makes it no longer accessible)',
  })
  @ApiResponseDecorator({
    status: 200,
    description: 'Short URL deactivated successfully',
    schema: {
      example: {
        success: true,
        message: 'Short URL deactivated successfully',
        data: null,
      },
    },
  })
  @ApiResponseDecorator({
    status: 404,
    description: 'Short URL not found or not owned by user',
  })
  async deactivateShortUrl(
    @Param('shortCode') shortCode: string,
    @User('id') userId: string,
  ): Promise<ApiResponse> {
    try {
      if (!shortCode) {
        throw new BadRequestException('Short code is required');
      }

      await this.urlShortenerService.deactivateUrl(shortCode, userId);

      return this.createSuccessResponse('Short URL deactivated successfully');
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error; // Keep not found errors as HttpExceptions
      }

      return this.handleServiceError(
        'deactivateShortUrl',
        error,
        'Failed to deactivate short URL',
      );
    }
  }

  // ========== CLEANUP ENDPOINT (Admin only) ==========
  @Post('url-shortener/cleanup')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 3600000 } }) // 5 requests per hour
  @ApiOperation({
    summary: 'Cleanup expired URLs',
    description: 'Removes all expired short URLs from the database (admin only)',
  })
  @ApiResponseDecorator({
    status: 200,
    description: 'Cleanup completed successfully',
    schema: {
      example: {
        success: true,
        message: 'Cleanup completed successfully',
        data: {
          deleted: 15,
        },
      },
    },
  })
  async cleanupExpiredUrls(): Promise<ApiResponse> {
    try {
      const result = await this.urlShortenerService.cleanupExpiredUrls();

      return this.createSuccessResponse(
        'Cleanup completed successfully',
        result,
      );
    } catch (error) {
      return this.handleServiceError(
        'cleanupExpiredUrls',
        error,
        'Failed to cleanup expired URLs',
      );
    }
  }
}