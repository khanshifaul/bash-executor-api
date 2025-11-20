import {
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../../database/prisma/prisma.service';
import { UsersService } from '../../users/users.service';

export interface AppJwtPayload {
  sub: string;
  email: string;
  role?: string;
  type?: string;
  permissions?: string[];
  iat?: number;
  exp?: number;
  rememberMe?: boolean;
  sessionId?: string;
  tokenFamily?: string;
}

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  session: any;
}

@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
  ) { }

  /**
   * Generate JWT tokens with session management
   */
  async generateTokens(
    userId: string,
    email: string,
    role: string,
    rememberMe = false,
    ipAddress?: string,
    userAgent?: string,
    deviceInfo?: any,
    additionalHeaders?: Record<string, string>,
  ): Promise<RefreshTokenResponse> {
    try {
      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      const refreshSecret =
        this.configService.get<string>('JWT_REFRESH_SECRET');

      if (!jwtSecret || !refreshSecret) {
        throw new Error('JWT secrets missing');
      }

      // Generate session expiry and refresh token expiry
      const sessionExpiryHours = rememberMe ? 30 * 24 : 24; // 30 days or 24 hours
      const refreshTokenExpiryHours = rememberMe ? 30 * 24 : 7 * 24; // 30 days or 7 days

      // Create user session with enhanced security
      const session = await this.createUserSession(
        userId,
        rememberMe,
        ipAddress,
        userAgent,
        deviceInfo,
        additionalHeaders,
      );

      // Create base payload
      const crypto = require('crypto');
      const tokenFamily = crypto.randomBytes(16).toString('hex');
      const payload: AppJwtPayload = {
        sub: userId,
        email,
        role: String(role || 'USER').toUpperCase(),
        rememberMe,
        sessionId: session.sessionId,
        tokenFamily,
      };

      this.logger.log(`🔑 ========== TOKEN GENERATION ==========`);
      this.logger.log(`🔑 Session ID: ${session.sessionId}`);
      this.logger.log(`🔑 Token Family: ${tokenFamily}`);
      this.logger.log(`🔑 User ID: ${userId}`);

      const accessTokenExpiresIn =
        this.configService.get<string>('JWT_EXPIRES_IN') || '15m';
      const refreshTokenExpiresIn = rememberMe
        ? this.configService.get<string>(
          'JWT_REFRESH_REMEMBER_ME_EXPIRES_IN',
        ) || '30d'
        : this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') || '7d';

      // Generate access token
      const accessToken = await this.jwtService.signAsync(payload as any, {
        secret: Buffer.from(jwtSecret, 'utf8'),
        expiresIn: accessTokenExpiresIn,
      } as any);

      // Generate refresh token with session info
      const refreshPayload: AppJwtPayload = {
        sub: userId,
        email,
        role: String(role || 'USER').toUpperCase(),
        rememberMe,
        sessionId: session.sessionId,
        tokenFamily: payload.tokenFamily,
      };

      const refreshToken = await this.jwtService.signAsync(refreshPayload as any, {
        secret: Buffer.from(refreshSecret, 'utf8'),
        expiresIn: refreshTokenExpiresIn,
      } as any);

      // Store refresh token in database
      await this.storeRefreshToken(
        session.id,
        refreshToken,
        payload.tokenFamily || '',
        ipAddress,
        userAgent,
      );

      this.logger.log(`✅ Generated tokens for session ${session.sessionId}`);
      return { accessToken, refreshToken, session };
    } catch (error) {
      this.logger.error(
        `Failed to generate tokens for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Refresh tokens using existing session (for refresh token endpoint)
   * This method reuses the existing session instead of creating a new one
   */
    async refreshTokensWithExistingSession(
    existingSession: any,
    userId: string,
    email: string,
    role: string,
    rememberMe: boolean,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<RefreshTokenResponse> {
    try {
      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

      if (!jwtSecret || !refreshSecret) {
        throw new Error('JWT secrets missing');
      }

      // Generate a NEW token family for rotation (keep same session)
      const crypto = require('crypto');
      const newTokenFamily = crypto.randomBytes(16).toString('hex');

      // Create base payload using existing session info
       const payload: AppJwtPayload = {
         sub: userId,
         email,
         role,
         rememberMe,
         sessionId: existingSession.sessionId, // Reuse existing sessionId
         tokenFamily: newTokenFamily, // New token family for rotation
       };

      this.logger.log(`🔄 ========== REFRESHING TOKENS ==========`);
      this.logger.log(`🔄 Existing Session ID: ${existingSession.sessionId}`);
      this.logger.log(`🔄 New Token Family: ${newTokenFamily}`);
      this.logger.log(`🔄 User ID: ${userId}`);

      const accessTokenExpiresIn = this.configService.get<string>('JWT_EXPIRES_IN') || '15m';
      const refreshTokenExpiresIn = rememberMe
        ? this.configService.get<string>('JWT_REFRESH_REMEMBER_ME_EXPIRES_IN') || '30d'
        : this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') || '7d';

      // Generate access token with current timestamp to ensure uniqueness
      const accessToken = await this.jwtService.signAsync({
        ...(payload as any),
        iat: Math.floor(Date.now() / 1000), // Force new issued at time
      } as any, {
        secret: Buffer.from(jwtSecret, 'utf8'),
        expiresIn: accessTokenExpiresIn,
      } as any);

      // Generate refresh token with existing session info
       const refreshPayload: AppJwtPayload = {
         sub: userId,
         email,
         role,
         rememberMe,
         sessionId: existingSession.sessionId, // Reuse existing sessionId
         tokenFamily: newTokenFamily, // New token family for rotation
       };

      const refreshToken = await this.jwtService.signAsync({
        ...(refreshPayload as any),
        iat: Math.floor(Date.now() / 1000), // Force new issued at time
      } as any, {
        secret: Buffer.from(refreshSecret, 'utf8'),
        expiresIn: refreshTokenExpiresIn,
      } as any);

      this.logger.log(`🔄 Generated new access token with iat: ${Math.floor(Date.now() / 1000)}`);
      this.logger.log(`🔄 Generated new refresh token with iat: ${Math.floor(Date.now() / 1000)}`);

      // Store refresh token in database (reusing existing session)
      await this.storeRefreshToken(
        existingSession.id, // Use existing session ID
        refreshToken,
        newTokenFamily,
        ipAddress,
        userAgent,
      );

      // Update session activity
      await this.prisma.userSession.update({
        where: { id: existingSession.id },
        data: { lastActivity: new Date() },
      });

      this.logger.log(`✅ Refreshed tokens for existing session ${existingSession.sessionId}`);
      return { accessToken, refreshToken, session: existingSession };
    } catch (error) {
      this.logger.error(`Failed to refresh tokens for user ${userId}:`, error.message);
      throw error;
    }
  }

  /**
   * Validate and consume a refresh token
   */
  async validateAndConsumeRefreshToken(
    refreshToken: string,
    userId: string,
  ): Promise<{ session: any; tokenFamily: string | null }> {
    try {
      this.logger.log(`🔍 ========== REFRESH TOKEN VALIDATION START ==========`);
      this.logger.log(`🔍 User ID: ${userId}`);
      this.logger.log(`🔍 Refresh Token Length: ${refreshToken.length}`);

      // First, verify the refresh token JWT to extract payload
      const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');
      if (!refreshSecret) {
        this.logger.error(`❌ JWT_REFRESH_SECRET missing`);
        throw new Error('JWT_REFRESH_SECRET missing');
      }

      this.logger.log(`🔍 Refresh secret length: ${refreshSecret.length}`);

      // Verify the JWT and extract payload
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: refreshSecret,
      });

      this.logger.log(`✅ JWT verified successfully`);
      this.logger.log(`🔍 JWT Payload - sessionId: ${payload.sessionId}, tokenFamily: ${payload.tokenFamily}`);

      if (!payload.sessionId || !payload.tokenFamily) {
        this.logger.error(`❌ Missing sessionId or tokenFamily in refresh token payload`);
        throw new UnauthorizedException('Invalid refresh token payload');
      }

      // Find the specific session using sessionId from JWT payload
      this.logger.log(`🔍 Looking for session with sessionId: ${payload.sessionId}, userId: ${userId}`);

      const session = await this.prisma.userSession.findUnique({
        where: {
          sessionId: payload.sessionId,
          userId,
          isActive: true,
          expiresAt: { gt: new Date() },
        },
        include: {
          refreshTokens: {
            where: { isActive: true },
          },
        },
      });

      if (!session) {
        this.logger.error(`❌ Session not found for sessionId: ${payload.sessionId}, userId: ${userId}`);

        // Let's check if the session exists at all (even if not active)
        const allSessions = await this.prisma.userSession.findMany({
          where: { userId },
          select: { id: true, sessionId: true, isActive: true, expiresAt: true }
        });
        this.logger.error(`Available sessions for user ${userId}:`, allSessions);

        throw new UnauthorizedException('Session not found or expired');
      }

      this.logger.log(`✅ Found session ${session.id} for user ${userId}`);
      this.logger.log(`📊 Session has ${session.refreshTokens.length} active refresh tokens`);

      if (session.refreshTokens.length === 0) {
        this.logger.error(`❌ No refresh tokens found in session ${session.id}`);
        throw new UnauthorizedException('No refresh tokens found for session');
      }

      // Find the specific refresh token record using tokenFamily from JWT payload
      const tokenRecord = session.refreshTokens.find(
        token => token.tokenFamily === payload.tokenFamily && token.isActive
      );

      if (!tokenRecord) {
        this.logger.error(`❌ No matching refresh token found in session ${session.id}`);
        this.logger.error(`🔍 Looking for tokenFamily: ${payload.tokenFamily}`);
        this.logger.error(`📋 Available active token families in session: ${session.refreshTokens.map(t => t.tokenFamily).join(', ')}`);

        // Let's also check if there are any inactive tokens
        const allTokensInSession = await this.prisma.refreshToken.findMany({
          where: { sessionId: session.id },
          select: { id: true, tokenFamily: true, isActive: true, expiresAt: true }
        });
        this.logger.error(`All tokens in session (active and inactive):`, allTokensInSession);

        // If no active token found but we have the session, it might be the first refresh
        // Let's check if there's only one token in the session (from initial login)
        if (session.refreshTokens.length === 1) {
          const singleToken = session.refreshTokens[0];
          this.logger.log(`🔄 Found single token in session, using it: ${singleToken.tokenFamily}`);

          // Mark the single token as used
          await this.prisma.refreshToken.update({
            where: { id: singleToken.id },
            data: {
              isActive: false,
              usedAt: new Date(),
            },
          });

          this.logger.log(`✅ Used single refresh token for session ${session.id}`);
          return { session, tokenFamily: singleToken.tokenFamily };
        }

        throw new UnauthorizedException('Refresh token not found or already used');
      }

      this.logger.log(`✅ Found matching refresh token ${tokenRecord.id} with tokenFamily ${tokenRecord.tokenFamily}`);

      // Check if token is expired
      if (tokenRecord.expiresAt < new Date()) {
        await this.prisma.refreshToken.update({
          where: { id: tokenRecord.id },
          data: { isActive: false },
        });
        throw new UnauthorizedException('Refresh token expired');
      }

      // Token is valid - mark it as used and update session
      await this.prisma.refreshToken.update({
        where: { id: tokenRecord.id },
        data: {
          isActive: false,
          usedAt: new Date(),
        },
      });

      // Update session activity
      await this.prisma.userSession.update({
        where: { id: session.id },
        data: { lastActivity: new Date() },
      });

      this.logger.log(
        `✅ Consumed valid refresh token for session ${session.id}`,
      );
      return { session, tokenFamily: tokenRecord.tokenFamily };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      this.logger.error(
        `Refresh token validation failed for user ${userId}:`,
        error.message,
      );
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }


  /**
   * Generate email verification token
   */
  async generateEmailVerificationToken(email: string): Promise<string> {
    try {
      const payload: AppJwtPayload = {
        email,
        type: 'verification',
        sub: email,
      };

      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      if (!jwtSecret) throw new Error('JWT_SECRET missing');

      const verificationToken = await this.jwtService.signAsync(payload as any, {
        secret: Buffer.from(jwtSecret, 'utf8'),
        expiresIn: '24h',
      });

      return verificationToken;
    } catch (error) {
      this.logger.error(
        'Failed to generate email verification token:',
        error.message,
      );
      throw new InternalServerErrorException(
        'Failed to generate verification token',
      );
    }
  }

  /**
   * Validate JWT secrets
   */
  validateJWTSecrets(): void {
    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    const jwtRefreshSecret =
      this.configService.get<string>('JWT_REFRESH_SECRET');

    this.logger.log(
      `🔐 [TokenService] Validating JWT secrets at ${new Date().toISOString()}`,
    );
    this.logger.log(
      `🔐 [TokenService] JWT_SECRET length: ${jwtSecret?.length || 'undefined'}`,
    );
    this.logger.log(
      `🔐 [TokenService] JWT_REFRESH_SECRET length: ${jwtRefreshSecret?.length || 'undefined'}`,
    );

    if (!jwtSecret || jwtSecret.length < 32) {
      this.logger.error(
        `❌ [TokenService] JWT_SECRET validation failed: ${!jwtSecret ? 'NOT FOUND' : `too short (${jwtSecret.length} chars)`}`,
      );
      throw new Error(
        `JWT_SECRET is missing or too short (minimum 32 characters). Found length: ${jwtSecret?.length || 'undefined'}`,
      );
    }

    if (!jwtRefreshSecret || jwtRefreshSecret.length < 32) {
      this.logger.error(
        `❌ [TokenService] JWT_REFRESH_SECRET validation failed: ${!jwtRefreshSecret ? 'NOT FOUND' : `too short (${jwtRefreshSecret.length} chars)`}`,
      );
      throw new Error(
        `JWT_REFRESH_SECRET is missing or too short (minimum 32 characters). Found length: ${jwtRefreshSecret?.length || 'undefined'}`,
      );
    }

    this.logger.log('✅ [TokenService] JWT secrets validated successfully');
  }

  /**
   * Decode and verify JWT token without throwing errors
   */
  async decodeToken(token: string): Promise<AppJwtPayload | null> {
    try {
      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      if (!jwtSecret) return null;

      const payload = await this.jwtService.verifyAsync(token, {
        secret: jwtSecret,
      });

      return payload;
    } catch (error) {
      this.logger.warn('Failed to decode token:', error.message);
      return null;
    }
  }

  /**
   * Check if token is expired
   */
  async isTokenExpired(token: string): Promise<boolean> {
    try {
      const decoded = await this.decodeToken(token);
      if (!decoded) return true;

      const now = Math.floor(Date.now() / 1000);
      return (decoded.exp || 0) < now;
    } catch (error) {
      return true;
    }
  }

  /**
   * Extract token metadata without verification
   */
  extractTokenMetadata(token: string): any {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      return {
        sub: payload.sub,
        email: payload.email,
        type: payload.type,
        permissions: payload.permissions,
        iat: payload.iat,
        exp: payload.exp,
        sessionId: payload.sessionId,
        tokenFamily: payload.tokenFamily,
      };
    } catch (error) {
      this.logger.warn('Failed to extract token metadata:', error.message);
      return null;
    }
  }

  /**
   * Create user session (internal helper)
   */
  private async createUserSession(
    userId: string,
    rememberMe = false,
    ipAddress?: string,
    userAgent?: string,
    deviceInfo?: any,
    additionalHeaders?: Record<string, string>,
  ): Promise<any> {
    try {
      // Generate device fingerprint
      const browserFingerprintHash = this.generateBrowserFingerprintHash(
        userAgent || '',
        additionalHeaders,
      );

      // Detect geolocation
      const geolocation = ipAddress
        ? await this.detectGeolocation(ipAddress)
        : {};

      // Calculate session expiry
      const sessionExpiryHours = rememberMe ? 30 * 24 : 24;
      const expiresAt = new Date(
        Date.now() + sessionExpiryHours * 60 * 60 * 1000,
      );

      // Generate unique session ID
      const crypto = require('crypto');
      const sessionId = crypto.randomBytes(32).toString('hex');

      // Create enhanced session data
      const sessionData = {
        userId,
        sessionId,
        deviceInfo: {
          ...deviceInfo,
          fingerprintGeneratedAt: new Date().toISOString(),
        },
        ipAddress,
        userAgent,
        location: geolocation.location,
        browserFingerprintHash,
        deviceFingerprintConfidence: 0.8,
        latitude: geolocation.latitude,
        longitude: geolocation.longitude,
        timezone: geolocation.timezone,
        rememberMe,
        expiresAt,
      };

      const session = await this.prisma.userSession.create({
        data: sessionData,
      });

      this.logger.log(`✅ ========== SESSION CREATED ==========`);
      this.logger.log(`✅ Session ID: ${sessionId}`);
      this.logger.log(`✅ Database Session ID: ${session.id}`);
      this.logger.log(`✅ User ID: ${userId}`);
      this.logger.log(`✅ Expires At: ${expiresAt}`);

      return session;
    } catch (error) {
      this.logger.error(
        `Failed to create user session for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
    * Store refresh token (internal helper)
    */
  private async storeRefreshToken(
    sessionId: string,
    refreshToken: string,
    tokenFamily: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    try {
      this.logger.log(`🔍 ========== STORING REFRESH TOKEN ==========`);
      this.logger.log(`🔍 Session ID: ${sessionId}`);
      this.logger.log(`🔍 Token Family: ${tokenFamily}`);
      this.logger.log(`🔍 Refresh Token Length: ${refreshToken.length}`);

      const tokenHash = await bcrypt.hash(refreshToken, 12);

      const rememberMeSession = await this.prisma.userSession.findUnique({
        where: { id: sessionId },
        select: { rememberMe: true },
      });
      const tokenExpiryHours = rememberMeSession?.rememberMe ? 30 * 24 : 7 * 24;
      const expiresAt = new Date(
        Date.now() + tokenExpiryHours * 60 * 60 * 1000,
      );

      const refreshTokenRecord = await this.prisma.refreshToken.create({
        data: {
          sessionId,
          tokenHash,
          tokenFamily,
          ipAddress,
          userAgent,
          expiresAt,
        },
      });

      this.logger.log(`✅ ========== REFRESH TOKEN STORED ==========`);
      this.logger.log(`✅ Token ID: ${refreshTokenRecord.id}`);
      this.logger.log(`✅ Session ID: ${sessionId}`);
      this.logger.log(`✅ Token Family: ${tokenFamily}`);
      this.logger.log(`✅ Expires At: ${refreshTokenRecord.expiresAt}`);

      return refreshTokenRecord;
    } catch (error) {
      this.logger.error(
        `Failed to store refresh token for session ${sessionId}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Generate browser fingerprint hash (helper)
   */
  private generateBrowserFingerprintHash(
    userAgent: string,
    additionalHeaders?: Record<string, string>,
  ): string {
    try {
      const crypto = require('crypto');
      const fingerprintData = {
        userAgent: userAgent || '',
        acceptLanguage: additionalHeaders?.['accept-language'] || '',
        acceptEncoding: additionalHeaders?.['accept-encoding'] || '',
        accept: additionalHeaders?.['accept'] || '',
        dnt: additionalHeaders?.['dnt'] || '',
        secChUa: additionalHeaders?.['sec-ch-ua'] || '',
        secChUaMobile: additionalHeaders?.['sec-ch-ua-mobile'] || '',
        secChUaPlatform: additionalHeaders?.['sec-ch-ua-platform'] || '',
      };

      const fingerprintString = JSON.stringify(
        fingerprintData,
        Object.keys(fingerprintData).sort(),
      );
      return crypto
        .createHash('sha256')
        .update(fingerprintString)
        .digest('hex');
    } catch (error) {
      this.logger.warn(
        'Failed to generate browser fingerprint hash:',
        error.message,
      );
      return '';
    }
  }

  /**
   * Detect geolocation from IP (helper)
   */
  private async detectGeolocation(ipAddress: string): Promise<{
    latitude?: number;
    longitude?: number;
    timezone?: string;
    location?: string;
  }> {
    try {
      if (this.isPrivateIP(ipAddress)) {
        return { location: 'Local Network' };
      }

      const timezone = this.guessTimezoneFromIP(ipAddress);
      return {
        timezone,
        location: this.getLocationFromTimezone(timezone),
      };
    } catch (error) {
      this.logger.warn(
        `Failed to detect geolocation for IP ${ipAddress}:`,
        error.message,
      );
      return {};
    }
  }

  private isPrivateIP(ip: string): boolean {
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^::1$/,
      /^fc00:/,
      /^fe80:/,
    ];
    return privateRanges.some((range) => range.test(ip));
  }

  private guessTimezoneFromIP(ip: string): string {
    if (!ip || ip === 'unknown' || ip === '::1') {
      return 'UTC';
    }
    return 'Asia/Dhaka';
  }

  private getLocationFromTimezone(timezone: string): string {
    const locationMap: Record<string, string> = {
      UTC: 'Unknown',
      'America/New_York': 'New York, US',
      'America/Los_Angeles': 'Los Angeles, US',
      'Europe/London': 'London, UK',
      'Europe/Paris': 'Paris, France',
      'Asia/Tokyo': 'Tokyo, Japan',
      'Asia/Shanghai': 'Shanghai, China',
      'Asia/Dhaka': 'Dhaka, Bangladesh',
      'Australia/Sydney': 'Sydney, Australia',
    };
    return locationMap[timezone] || timezone;
  }
}
