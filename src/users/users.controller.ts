// src/users/users.controller.ts
// src/users/users.controller.ts
import {
  BadRequestException,
  Controller,
  Get,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import type { Request } from 'express';
import { AccessTokenGuard } from 'src/common/guards/access-token.guard';
import { User } from '../common/decorators/user.decorator';

import { UsersService } from './users.service';

interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  code?: string;
}

@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  private createSuccessResponse<T>(message: string, data?: T): ApiResponse<T> {
    return { success: true, message, data };
  }

  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth('access-token')
  @Get('profile')
  @ApiOperation({ summary: 'Get user profile' })
  @ApiResponse({
    status: 200,
    description: 'Profile retrieved successfully',
    schema: {
      example: {
        success: true,
        message: 'Profile retrieved successfully',
        data: {
          id: 'cmeiwdhbw0001jxvmdj1mq6r8',
          email: 'khanshifaul@gmail.com',
          name: 'Shifaul Khan',
          avatar: 'https://gravatar.com/avatar/...jpg',
          provider: 'local',
          isEmailVerified: true,
          isTwoFactorEnabled: false,
          role: 'USER',
          createdAt: '2023-01-01T00:00:00.000Z',
          updatedAt: '2023-01-01T00:00:00.000Z',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'User not found',
    schema: {
      example: {
        success: false,
        message: 'User not found',
        error: 'NOT_FOUND',
        code: 'USER_NOT_FOUND',
      },
    },
  })
  async getProfile(@User() user: any, @Req() request: Request): Promise<ApiResponse> {
    const userIdToQuery = user.id;
    const userData = await this.usersService.findById(userIdToQuery);

    if (!userData) {
      throw new BadRequestException('User not found');
    }

    // Remove sensitive fields
    const {
      password,
      verificationToken,
      twoFactorSecret,
      resetToken,
      resetTokenExpires,
      ...profile
    } = userData;

    const responseData: any = { ...profile };

    return this.createSuccessResponse('Profile retrieved successfully', responseData);
  }
}

