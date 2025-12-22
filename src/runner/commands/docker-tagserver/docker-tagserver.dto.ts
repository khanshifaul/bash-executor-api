import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsOptional, IsArray, IsBoolean, ValidateIf, Matches, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

/**
 * Docker Tagserver Create Command DTO
 */
export class DockerTagserverCreateDto {
  @ApiProperty({
    type: [String],
    example: 'example.com',
  })
  @IsString({ message: 'domains must be a string' })
  domains: string;

  @ApiProperty({
    type: String,
    example: 'user123',
  })
  @IsString({ message: 'config must be a string' })
  config: string;

  @ApiProperty({
    type: String,
    example: 'my-tagserver',
  })
  @IsString({ message: 'name must be a string' })
  name: string;

  @ApiProperty({
    type: String,
    example: 'user123',
  })
  @IsString({ message: 'user must be a string' })
  user: string;

  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver List Command DTO
 */
export class DockerTagserverListDto {
  @ApiProperty({
    type: [String],
    example: 'user123',
  })
  @IsString()
  @IsOptional()
  user?: string;

  @ApiProperty({
    type: Boolean,
    example: false,
  })
  @IsBoolean()
  @IsOptional()
  all?: boolean = false;

  @ApiProperty({
    type: Boolean,
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Get Command DTO
 */
export class DockerTagserverGetDto {
  @ApiProperty({
    type: String,
    example: 'container-id-123',
  })
  @IsString()
  @IsOptional()
  containerId?: string;

  @ApiProperty({
    type: String,
    example: 'my-tagserver',
  })
  @IsString()
  @IsOptional()
  containerName?: string;

  @ApiProperty({
    type: String,
    example: 'user123',
  })
  @IsString()
  @IsOptional()
  user?: string;

  @ApiProperty({
    type: Boolean,
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Container Control DTO (Stop, Start, Restart, Delete)
 */
export class DockerTagserverContainerControlDto {
  @ApiProperty({
    type: String,
    example: 'container-id-123',
  })
  @IsString()
  @IsOptional()
  containerId?: string;

  @ApiProperty({
    type: String,
    example: 'my-tagserver',
  })
  @IsString()
  @IsOptional()
  containerName?: string;

  @ApiProperty({
    type: String,
    example: 'user123',
  })
  @IsString()
  @IsOptional()
  user?: string;

  @ApiProperty({
    type: Boolean,
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Logs Command DTO
 */
export class DockerTagserverLogsDto {
  @ApiProperty({
    type: String,
    example: 'container-id-123',
  })
  @IsString()
  @IsOptional()
  containerId?: string;

  @ApiProperty({
    type: String,
    example: 'my-tagserver',
  })
  @IsString()
  @IsOptional()
  containerName?: string;

  @ApiProperty({
    type: String,
    example: 'user123',
  })
  @IsString()
  @IsOptional()
  user?: string;
}

/**
 * Docker Tagserver Add Custom Domain DTO
 */
export class DockerTagserverAddCustomDomainDto {
  @ApiProperty({
    type: String,
    example: 'container-id-123',
  })
  @IsString()
  @IsOptional()
  containerId?: string;

  @ApiProperty({
    type: String,
    example: 'my-tagserver',
  })
  @IsString()
  @IsOptional()
  containerName?: string;

  @ApiProperty({
    type: String,
    example: 'user123',
  })
  @IsString()
  @IsOptional()
  user?: string;

  @ApiProperty({
    type: [String],
    example: ['example.com', 'www.example.com'],
  })
  @IsString({ each: true })
  @IsArray()
  domains: string[];

  @ApiProperty({
    type: Boolean,
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Remove Custom Domain DTO
 */
export class DockerTagserverRemoveCustomDomainDto {
  @ApiProperty({
    type: String,
    example: 'container-id-123',
  })
  @IsString()
  @IsOptional()
  containerId?: string;

  @ApiProperty({
    type: String,
    example: 'my-tagserver',
  })
  @IsString()
  @IsOptional()
  containerName?: string;

  @ApiProperty({
    type: String,
    example: 'user123',
  })
  @IsString()
  @IsOptional()
  user?: string;

  @ApiProperty({
    type: [String],
    example: ['example.com', 'www.example.com'],
  })
  @IsString({ each: true })
  @IsArray()
  domains: string[];

  @ApiProperty({
    type: Boolean,
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Count Logs Command DTO
 */
export class DockerTagserverCountLogsDto {
  @ApiProperty({
    type: String,
    example: 'container-id-123',
  })
  @IsString()
  @IsOptional()
  containerId?: string;

  @ApiProperty({
    type: String,
    example: 'my-tagserver',
  })
  @IsString()
  @IsOptional()
  containerName?: string;

  @ApiProperty({
    type: String,
    example: 'user123',
  })
  @IsString()
  @IsOptional()
  user?: string;

  @ApiProperty({
    type: String,
    example: 'error',
  })
  @IsString()
  @IsOptional()
  pattern?: string;

  @ApiProperty({
    type: String,
    example: '2024-01-01T00:00:00Z',
  })
  @IsString()
  @IsOptional()
  since?: string;

  @ApiProperty({
    type: String,
    example: '2024-01-02T00:00:00Z',
  })
  @IsString()
  @IsOptional()
  until?: string;

  @ApiProperty({
    type: Boolean,
    example: false,
  })
  @IsBoolean()
  @IsOptional()
  all?: boolean = false;

  @ApiProperty({
    type: Boolean,
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Update Nginx Command DTO
 */
export class DockerTagserverUpdateNginxDto {
  @ApiProperty({
    type: String,
    example: 'container-id-123',
  })
  @IsString()
  @IsOptional()
  containerId?: string;

  @ApiProperty({
    type: String,
    example: 'my-tagserver',
  })
  @IsString()
  @IsOptional()
  containerName?: string;

  @ApiProperty({
    type: String,
    example: 'user123',
  })
  @IsString()
  @IsOptional()
  user?: string;
}

/**
 * Docker Tagserver Verify DNS Tasks Command DTO (no arguments)
 */
export class DockerTagserverVerifyDnsTasksDto { }

/**
 * Docker Tagserver Retry SSL Command DTO
 */
export class DockerTagserverRetrySslDto {
  @ApiProperty({
    type: Boolean,
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Cron Setup Command DTO
 */
export class DockerTagserverCronSetupDto { }
