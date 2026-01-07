import {
  IsArray,
  IsDateString,
  IsNumber,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
  ValidateIf,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateApiKeyDto {
  @ApiProperty({ description: 'Name of the API key' })
  @IsString()
  @MinLength(3)
  @MaxLength(100)
  name: string;

  @ApiPropertyOptional({ description: 'Description of the API key', maxLength: 500 })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;

  @ApiProperty({
    description: 'Permissions granted (e.g., ["runner:execute"])',
    type: [String],
    example: ['runner:execute', 'user:read'],
  })
  @IsArray()
  @IsString({ each: true })
  @MaxLength(50, { each: true })
  permissions: string[] = [];

  @ApiProperty({
    description: 'Scopes (e.g., ["read", "write"])',
    type: [String],
    example: ['read', 'write'],
  })
  @IsArray()
  @IsString({ each: true })
  @MaxLength(50, { each: true })
  scopes: string[] = [];

  @ApiPropertyOptional({
    description: 'Usage limit (null/unlimited if omitted)',
    example: 1000,
  })
  @IsOptional()
  @IsNumber({}, { message: 'Must be a number' })
  usageLimit?: number;


}