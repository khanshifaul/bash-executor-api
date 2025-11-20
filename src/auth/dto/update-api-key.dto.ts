import {
  IsArray,
  IsBoolean,
  IsDateString,
  IsNumber,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateApiKeyDto {
  @ApiPropertyOptional({ description: 'New name of the API key', maxLength: 100 })
  @IsOptional()
  @IsString()
  @MinLength(3)
  @MaxLength(100)
  name?: string;

  @ApiPropertyOptional({ description: 'New description', maxLength: 500 })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;

  @ApiPropertyOptional({
    description: 'Updated permissions',
    type: [String],
    example: ['runner:execute'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  @MaxLength(50, { each: true })
  permissions?: string[];

  @ApiPropertyOptional({
    description: 'Updated scopes',
    type: [String],
    example: ['read', 'write'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  @MaxLength(50, { each: true })
  scopes?: string[];

  @ApiPropertyOptional({ description: 'New usage limit', example: 1000 })
  @IsOptional()
  @IsNumber({}, { message: 'Must be a number' })
  usageLimit?: number;

  @ApiPropertyOptional({ description: 'New expiration date (ISO 8601)', example: '2025-12-31T23:59:59Z' })
  @IsOptional()
  @IsDateString()
  expiresAt?: string;

  @ApiPropertyOptional({ description: 'Activate/deactivate the key' })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}