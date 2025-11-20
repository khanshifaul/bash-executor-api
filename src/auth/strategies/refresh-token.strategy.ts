// src/auth/strategies/refresh-token.strategy.ts
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from 'src/database/prisma/prisma.service';
import { LoggerService } from 'src/utils/logger/logger.service';

export interface RefreshTokenPayload {
    sub: string;
    email: string;
    role?: string;
    type?: string;
    permissions?: string[];
    iat?: number;
    exp?: number;
    sessionId?: string;
    tokenFamily?: string;
    rememberMe?: boolean;
}

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(Strategy, 'refresh-token') {
    private readonly logger = new Logger(RefreshTokenStrategy.name);

    constructor(
        private readonly configService: ConfigService,
        private readonly prisma: PrismaService,
        private readonly loggerService: LoggerService,
    ) {
        const refreshSecret = configService.get<string>('JWT_REFRESH_SECRET');

        if (!refreshSecret) {
            throw new Error(
                'JWT_REFRESH_SECRET is not configured via ConfigService. Please set JWT_REFRESH_SECRET in your configuration.',
            );
        }

        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: refreshSecret,
            passReqToCallback: true,
        });

        this.logger.log('Refresh token strategy configured successfully via ConfigService.');
    }

    async validate(req: any, payload: RefreshTokenPayload) {
        const role = String(payload.role || 'USER').toUpperCase();

        this.logger.log(`🔍 Validating refresh token for user: ${payload.sub}, session: ${payload.sessionId}`);

        // Validate session if sessionId is present in payload
        if (payload.sessionId) {
            try {
                const session = await this.prisma.userSession.findUnique({
                    where: { sessionId: payload.sessionId },
                });

                if (!session) {
                    this.loggerService.security(
                        'REFRESH_SESSION_NOT_FOUND',
                        {
                            sessionId: payload.sessionId,
                        },
                        payload.sub,
                    );
                    throw new UnauthorizedException('Session not found');
                }

                if (!session.isActive) {
                    this.loggerService.security(
                        'REFRESH_SESSION_INACTIVE',
                        {
                            sessionId: payload.sessionId,
                            invalidatedAt: session.invalidatedAt,
                            invalidationReason: session.invalidationReason,
                        },
                        payload.sub,
                    );
                    throw new UnauthorizedException('Session is inactive');
                }

                if (session.expiresAt < new Date()) {
                    this.loggerService.security(
                        'REFRESH_SESSION_EXPIRED',
                        {
                            sessionId: payload.sessionId,
                            expiresAt: session.expiresAt,
                        },
                        payload.sub,
                    );
                    throw new UnauthorizedException('Session has expired');
                }

                // Update session activity
                await this.prisma.userSession.update({
                    where: { id: session.id },
                    data: { lastActivity: new Date() },
                });

                // Log successful session validation
                this.loggerService.security(
                    'REFRESH_SESSION_VALIDATED',
                    {
                        sessionId: payload.sessionId,
                        riskScore: session.riskScore,
                    },
                    payload.sub,
                );
            } catch (error) {
                if (error instanceof UnauthorizedException) {
                    throw error;
                }
                this.logger.error(
                    `Refresh token session validation failed for user ${payload.sub}:`,
                    error.message,
                );
                throw new UnauthorizedException('Session validation failed');
            }
        }

        return {
            id: payload.sub,
            email: payload.email,
            role: role,
            type: payload.type,
            permissions: payload.permissions || [],
            rememberMe: payload.rememberMe || false,
            sessionId: payload.sessionId,
            tokenFamily: payload.tokenFamily,
        };
    }
}