import { IsString, IsOptional, IsArray, IsBoolean, ValidateIf, Matches } from 'class-validator';

/**
 * Docker Tagserver Create Command DTO
 */
export class DockerTagserverCreateDto {
  @IsString({ message: 'domains must be a string' })
  domains: string;

  @IsString({ message: 'config must be a string' })
  config: string;

  @IsString({ message: 'name must be a string' })
  name: string;

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
  @IsString()
  @IsOptional()
  user?: string;

  @IsBoolean()
  @IsOptional()
  all?: boolean = false;

  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Get Command DTO
 */
export class DockerTagserverGetDto {
  @IsString()
  @IsOptional()
  containerId?: string;

  @IsString()
  @IsOptional()
  containerName?: string;

  @IsString()
  @IsOptional()
  user?: string;

  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Container Control DTO (Stop, Start, Restart, Delete)
 */
export class DockerTagserverContainerControlDto {
  @IsString()
  @IsOptional()
  containerId?: string;

  @IsString()
  @IsOptional()
  containerName?: string;

  @IsString()
  @IsOptional()
  user?: string;

  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Logs Command DTO
 */
export class DockerTagserverLogsDto {
  @IsString()
  @IsOptional()
  containerId?: string;

  @IsString()
  @IsOptional()
  containerName?: string;

  @IsString()
  @IsOptional()
  user?: string;

  @IsBoolean()
  @IsOptional()
  follow?: boolean = false;

  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Add Custom Domain DTO
 */
export class DockerTagserverAddCustomDomainDto {
  @IsString()
  @IsOptional()
  containerId?: string;

  @IsString()
  @IsOptional()
  containerName?: string;

  @IsString()
  @IsOptional()
  user?: string;

  @IsString({ each: true })
  @IsArray()
  domains: string[];

  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Count Logs Command DTO
 */
export class DockerTagserverCountLogsDto {
  @IsString()
  @IsOptional()
  containerId?: string;

  @IsString()
  @IsOptional()
  containerName?: string;

  @IsString()
  @IsOptional()
  user?: string;

  @IsString()
  @IsOptional()
  pattern?: string;

  @IsString()
  @IsOptional()
  since?: string;

  @IsString()
  @IsOptional()
  until?: string;

  @IsBoolean()
  @IsOptional()
  json?: boolean = true;
}

/**
 * Docker Tagserver Update Nginx Command DTO
 */
export class DockerTagserverUpdateNginxDto {
  @IsString()
  @IsOptional()
  containerId?: string;

  @IsString()
  @IsOptional()
  containerName?: string;

  @IsString()
  @IsOptional()
  user?: string;
}

/**
 * Docker Tagserver Verify DNS Tasks Command DTO (no arguments)
 */
export class DockerTagserverVerifyDnsTasksDto {}
