import {
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../../database/prisma/prisma.service';
import { CreateApiKeyDto } from '../dto/create-api-key.dto';
import { UpdateApiKeyDto } from '../dto/update-api-key.dto';
import * as crypto from 'node:crypto';

@Injectable()
export class ApiKeyService {
  constructor(private readonly prisma: PrismaService) { }

  async create(userId: string, dto: CreateApiKeyDto) {
    const key = crypto.randomBytes(32).toString('hex');

    const apiKey = await this.prisma.apiKey.create({
      data: {
        key,
        name: dto.name,
        description: dto.description || null,
        userId,
        permissions: dto.permissions || [],
        scopes: dto.scopes || [],
        usageLimit: dto.usageLimit ?? null,
        expiresAt: dto.expiresAt ? new Date(dto.expiresAt) : null,
      },
    });

    return apiKey;
  }

  async findAll(userId: string) {
    return this.prisma.apiKey.findMany({
      where: {
        userId,
        isActive: true,
      },
      select: {
        id: true,
        name: true,
        description: true,
        permissions: true,
        scopes: true,
        usageCount: true,
        usageLimit: true,
        lastUsedAt: true,
        expiresAt: true,
        createdAt: true,
        updatedAt: true,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });
  }

  async findOne(userId: string, id: string) {
    const apiKey = await this.prisma.apiKey.findUnique({
      where: { id },
    });

    if (!apiKey || apiKey.userId !== userId) {
      throw new NotFoundException('API key not found');
    }

    // Return the full key object including the secret key
    return apiKey;
  }

  async update(userId: string, id: string, dto: UpdateApiKeyDto) {
    const apiKey = await this.prisma.apiKey.findUnique({
      where: { id },
    });

    if (!apiKey || apiKey.userId !== userId) {
      throw new NotFoundException('API key not found');
    }

    return this.prisma.apiKey.update({
      where: { id },
      data: {
        name: dto.name,
        description: dto.description || null,
        permissions: dto.permissions,
        scopes: dto.scopes,
        usageLimit: dto.usageLimit ?? null,
        expiresAt: dto.expiresAt ? new Date(dto.expiresAt) : null,
        isActive: dto.isActive ?? undefined,
      },
    });
  }

  async remove(userId: string, id: string) {
    const apiKey = await this.prisma.apiKey.findUnique({
      where: { id },
    });

    if (!apiKey || apiKey.userId !== userId) {
      throw new NotFoundException('API key not found');
    }

    return this.prisma.apiKey.delete({
      where: { id },
    });
  }
}