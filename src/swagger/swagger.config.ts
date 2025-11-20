// src/swagger/swagger.config.ts
import { DocumentBuilder } from '@nestjs/swagger';

export const SWAGGER_CONFIG = {
  title: 'Runner NestJS API',
  description:
    'A robust backend API with authentication, command execution, and real-time updates',
  version: '1.0.0',
  tags: [
    {
      name: 'Application',
      description: 'General application endpoints',
    },
    {
      name: 'Authentication',
      description: 'User authentication and authorization',
    },
    {
      name: 'Runner Commands',
      description: 'Secure command execution endpoints',
    },
    {
      name: 'Runner',
      description: 'Runner service management endpoints',
    },
  ],
  // Force tag order with OpenAPI extensions
  'x-tagGroups': [
    {
      name: 'Core Application',
      tags: ['Application'],
    },
    {
      name: 'Authentication',
      tags: [
        'Authentication',
        'OAuth Authentication',
        'Two-Factor Authentication',
        'Session Management',
      ],
    },
    {
      name: 'Command Execution',
      tags: ['Runner Commands'],
    },
    {
      name: 'Runner Service',
      tags: ['Runner'],
    },
  ],
};

export function createSwaggerConfig(baseUrl: string) {
  const config = new DocumentBuilder()
    .setTitle(SWAGGER_CONFIG.title)
    .setDescription(SWAGGER_CONFIG.description)
    .setVersion(SWAGGER_CONFIG.version)

    // ✅ Main JWT Auth (for access tokens)
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Enter your **access token**',
      },
      'access-token',
    )

    // ✅ Refresh Token Scheme (critical for /refresh)
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Enter your **refresh token**',
      },
      'refresh-token',
    )

    // Add tag groups to force order in Swagger UI
    .addServer(baseUrl)
    .setExternalDoc('API Documentation', `${baseUrl}/api/docs`);
  return config;
}
