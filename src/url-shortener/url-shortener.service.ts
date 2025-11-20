import { Injectable, BadRequestException, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../database/prisma/prisma.service';
import { LoggerService } from '../utils/logger/logger.service';

export interface CreateShortUrlDto {
  originalUrl: string;
  userId?: string;
  expiresInHours?: number;
}

export interface ShortUrlResponse {
  shortCode: string;
  shortUrl: string;
  originalUrl: string;
  expiresAt?: Date;
  clickCount: number;
}

export interface AnalyticsData {
  shortCode: string;
  clickCount: number;
  createdAt: Date;
  expiresAt?: Date;
  isActive: boolean;
}

@Injectable()
export class UrlShortenerService {
  private readonly ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  private readonly DEFAULT_EXPIRY_HOURS = 24;
  private readonly MAX_RETRIES = 10;

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly logger: LoggerService,
  ) {}

  /**
   * Creates a shortened URL with collision-resistant short code generation
   */
  async createShortUrl(dto: CreateShortUrlDto): Promise<ShortUrlResponse> {
    // Validate URL format
    this.validateUrl(dto.originalUrl);

    // Generate unique short code with retries
    const shortCode = await this.generateUniqueShortCode();
    
    // Calculate expiration date
    const expiresAt = dto.expiresInHours 
      ? new Date(Date.now() + dto.expiresInHours * 60 * 60 * 1000)
      : null;

    try {
      const shortener = await this.prisma.urlShortener.create({
        data: {
          shortCode,
          originalUrl: dto.originalUrl,
          userId: dto.userId || null,
          expiresAt,
          isActive: true,
          clickCount: 0,
        },
      });

      const shortUrl = this.buildShortUrl(shortCode);

      this.logger.info(
        `Created short URL: ${shortCode}`,
        'UrlShortenerService',
        { shortCode, userId: dto.userId }
      );

      return {
        shortCode: shortener.shortCode,
        shortUrl,
        originalUrl: shortener.originalUrl,
        expiresAt: shortener.expiresAt || undefined,
        clickCount: shortener.clickCount,
      };
    } catch (error) {
      this.logger.error(
        'Failed to create short URL',
        'UrlShortenerService',
        { error: error.message, ...dto }
      );
      throw new BadRequestException('Failed to create short URL');
    }
  }

  /**
   * Retrieves original URL and updates click count
   */
  async getOriginalUrl(shortCode: string): Promise<string> {
    try {
      const result = await this.prisma.$queryRaw<any>`
        SELECT * FROM "url_shortener" WHERE "shortCode" = ${shortCode}
      `;

      const shortener = result[0];

      if (!shortener) {
        this.logger.warn(`Short code not found: ${shortCode}`, 'UrlShortenerService');
        throw new NotFoundException('Short URL not found');
      }

      // Check if URL is expired
      if (shortener.expiresAt && new Date(shortener.expiresAt) < new Date()) {
        await this.prisma.$queryRaw`
          UPDATE "url_shortener" 
          SET "isActive" = false, "updatedAt" = NOW() 
          WHERE "id" = ${shortener.id}
        `;
        
        this.logger.warn(`Expired short URL accessed: ${shortCode}`, 'UrlShortenerService');
        throw new NotFoundException('Short URL has expired');
      }

      // Check if URL is inactive
      if (!shortener.isActive) {
        this.logger.warn(`Inactive short URL accessed: ${shortCode}`, 'UrlShortenerService');
        throw new NotFoundException('Short URL is no longer active');
      }

      // Update click count
      await this.prisma.$queryRaw`
        UPDATE "url_shortener" 
        SET "clickCount" = "clickCount" + 1, "updatedAt" = NOW() 
        WHERE "id" = ${shortener.id}
      `;

      this.logger.info(
        `Short URL accessed: ${shortCode} (click count: ${shortener.clickCount + 1})`,
        'UrlShortenerService',
        { shortCode, clickCount: shortener.clickCount + 1 }
      );

      return shortener.originalUrl;
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      
      this.logger.error(
        'Failed to retrieve original URL',
        'UrlShortenerService',
        { error: error.message, shortCode }
      );
      throw new BadRequestException('Failed to retrieve short URL');
    }
  }

  /**
   * Gets analytics data for a short URL (protected endpoint)
   */
  async getAnalytics(shortCode: string, userId?: string, userRole?: string): Promise<AnalyticsData> {
    try {
      const result = await this.prisma.$queryRaw<any>`
        SELECT * FROM "url_shortener" WHERE "shortCode" = ${shortCode}
      `;

      const shortener = result[0];

      if (!shortener) {
        throw new NotFoundException('Short URL not found');
      }

      // Check if user owns this URL (if userId provided and not admin)
      if (userId && userRole !== 'ADMIN' && shortener.userId !== userId) {
        throw new NotFoundException('Short URL not found');
      }

      return {
        shortCode: shortener.shortCode,
        clickCount: shortener.clickCount,
        createdAt: shortener.createdAt,
        expiresAt: shortener.expiresAt,
        isActive: shortener.isActive,
      };
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      
      this.logger.error(
        'Failed to get analytics',
        'UrlShortenerService',
        { error: error.message, shortCode, userId }
      );
      throw new BadRequestException('Failed to get analytics');
    }
  }

  /**
   * Gets all shortened URLs (admin only)
   */
  async getAllShortenedUrls(): Promise<Array<AnalyticsData & { originalUrl: string; userId?: string }>> {
    try {
      const results = await this.prisma.$queryRaw<any>`
        SELECT
          "shortCode",
          "originalUrl",
          "userId",
          "clickCount",
          "createdAt",
          "expiresAt",
          "isActive"
        FROM "url_shortener"
        ORDER BY "createdAt" DESC
        LIMIT 1000
      `;

      return results.map((shortener: any) => ({
        shortCode: shortener.shortCode,
        originalUrl: shortener.originalUrl,
        userId: shortener.userId,
        clickCount: shortener.clickCount,
        createdAt: shortener.createdAt,
        expiresAt: shortener.expiresAt,
        isActive: shortener.isActive,
      }));
    } catch (error) {
      this.logger.error(
        'Failed to get all shortened URLs',
        'UrlShortenerService',
        { error: error.message }
      );
      throw new BadRequestException('Failed to retrieve shortened URLs');
    }
  }

  /**
   * Generates collision-resistant 6-8 character codes
   */
  private async generateUniqueShortCode(): Promise<string> {
    let attempts = 0;
    
    while (attempts < this.MAX_RETRIES) {
      const shortCode = this.generateShortCode();
      const result = await this.prisma.$queryRaw<any>`
        SELECT id FROM "url_shortener" WHERE "shortCode" = ${shortCode}
      `;

      if (!result || result.length === 0) {
        return shortCode;
      }

      attempts++;
    }

    // If we reach here, all retries failed, try with longer codes
    for (let length = 6; length <= 8; length++) {
      for (let i = 0; i < 100; i++) {
        const shortCode = this.generateShortCode(length);
        const result = await this.prisma.$queryRaw<any>`
          SELECT id FROM "url_shortener" WHERE "shortCode" = ${shortCode}
        `;

        if (!result || result.length === 0) {
          return shortCode;
        }
      }
    }

    throw new BadRequestException('Failed to generate unique short code');
  }

  /**
   * Generates a random short code of specified length
   */
  private generateShortCode(length: number = 6): string {
    const code: string[] = [];
    const alphabetLength = this.ALPHABET.length;
    
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * alphabetLength);
      code.push(this.ALPHABET[randomIndex]);
    }
    
    return code.join('');
  }

  /**
   * Cleans up expired URLs (can be called by cron job)
   */
  async cleanupExpiredUrls(): Promise<{ deleted: number }> {
    try {
      const result = await this.prisma.$queryRaw<any>`
        DELETE FROM "url_shortener" 
        WHERE "expiresAt" IS NOT NULL AND "expiresAt" < NOW()
      `;

      this.logger.info(
        `Cleaned up expired URLs`,
        'UrlShortenerService',
        { deletedCount: result.length || 0 }
      );

      return { deleted: result.length || 0 };
    } catch (error) {
      this.logger.error(
        'Failed to cleanup expired URLs',
        'UrlShortenerService',
        { error: error.message }
      );
      throw new BadRequestException('Failed to cleanup expired URLs');
    }
  }

  /**
   * Validates URL format (must be http/https)
   */
  private validateUrl(url: string): void {
    try {
      const urlObject = new URL(url);
      if (!['http:', 'https:'].includes(urlObject.protocol)) {
        throw new Error('Invalid protocol');
      }
    } catch {
      throw new BadRequestException('Invalid URL format. URL must be a valid http/https URL');
    }
  }

  /**
   * Builds full short URL from short code
   */
  private buildShortUrl(shortCode: string): string {
    const baseUrl = this.configService.get<string>('BACKEND_URL', 'http://localhost:40000');
    return `${baseUrl}/s/${shortCode}`;
  }

  /**
   * Deactivates a short URL (for admin/user management)
   */
  async deactivateUrl(shortCode: string, userId?: string): Promise<void> {
    try {
      const result = await this.prisma.$queryRaw<any>`
        SELECT * FROM "url_shortener" WHERE "shortCode" = ${shortCode}
      `;

      const shortener = result[0];

      if (!shortener) {
        throw new NotFoundException('Short URL not found');
      }

      // Check ownership if userId provided
      if (userId && shortener.userId !== userId) {
        throw new NotFoundException('Short URL not found');
      }

      await this.prisma.$queryRaw`
        UPDATE "url_shortener" 
        SET "isActive" = false, "updatedAt" = NOW() 
        WHERE "id" = ${shortener.id}
      `;

      this.logger.info(
        `Deactivated short URL: ${shortCode}`,
        'UrlShortenerService',
        { shortCode, userId }
      );
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      
      this.logger.error(
        'Failed to deactivate URL',
        'UrlShortenerService',
        { error: error.message, shortCode, userId }
      );
      throw new BadRequestException('Failed to deactivate URL');
    }
  }
}