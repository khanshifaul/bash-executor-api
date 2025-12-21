import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import { CommandResponseDto } from '../../dto/command-response.dto';
import { DockerTagserverCommandHandler } from './docker-tagserver.handler';
import {
  DockerTagserverAddCustomDomainDto,
  DockerTagserverContainerControlDto,
  DockerTagserverCountLogsDto,
  DockerTagserverCreateDto,
  DockerTagserverGetDto,
  DockerTagserverListDto,
  DockerTagserverLogsDto,
  DockerTagserverUpdateNginxDto,
  DockerTagserverVerifyDnsTasksDto,
} from './docker-tagserver.dto';

@ApiTags('Runner Commands')
@ApiBearerAuth('access-token')
@ApiSecurity('x-api-key')
@Controller('commands/docker-tagserver')
export class DockerTagserverController {
  constructor(private readonly handler: DockerTagserverCommandHandler) { }

  @Post('create')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Create a new tag server container',
    description: 'Start a new tag server container with domain routing and SSL',
  })
  @ApiBody({ type: DockerTagserverCreateDto })
  @ApiResponse({
    status: 200,
    description: 'Container created successfully',
    schema: {
      type: 'object',
      properties: {
        stdout: {
          oneOf: [{ type: 'string' }, { type: 'object' }],
        },
        stderr: { type: 'string' },
        exitCode: { type: 'number' },
        duration: { type: 'number' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid parameters',
  })
  async create(@Body() dto: DockerTagserverCreateDto): Promise<CommandResponseDto> {
    return this.handler.handleCreate(dto);
  }

  @Post('list')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'List all containers for a user',
    description: 'List all containers with detailed information',
  })
  @ApiBody({ type: DockerTagserverListDto })
  @ApiResponse({
    status: 200,
    description: 'Container list retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        stdout: { type: 'string' },
        stderr: { type: 'string' },
        exitCode: { type: 'number' },
        duration: { type: 'number' },
      },
    },
  })
  async list(@Body() dto: DockerTagserverListDto): Promise<CommandResponseDto> {
    return this.handler.handleList(dto);
  }

  @Post('get')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get container details',
    description: 'Get detailed information about a specific container by ID or name',
  })
  @ApiBody({ type: DockerTagserverGetDto })
  @ApiResponse({
    status: 200,
    description: 'Container details retrieved successfully',
  })
  async get(@Body() dto: DockerTagserverGetDto): Promise<CommandResponseDto> {
    return this.handler.handleGet(dto);
  }

  @Post('stop')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Stop a running container',
    description: 'Stop a running container gracefully',
  })
  @ApiBody({ type: DockerTagserverContainerControlDto })
  @ApiResponse({
    status: 200,
    description: 'Container stopped successfully',
  })
  async stop(@Body() dto: DockerTagserverContainerControlDto): Promise<CommandResponseDto> {
    return this.handler.handleStop(dto);
  }

  @Post('start')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Start a stopped container',
    description: 'Start a previously stopped container',
  })
  @ApiBody({ type: DockerTagserverContainerControlDto })
  @ApiResponse({
    status: 200,
    description: 'Container started successfully',
  })
  async start(@Body() dto: DockerTagserverContainerControlDto): Promise<CommandResponseDto> {
    return this.handler.handleStart(dto);
  }

  @Post('restart')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Restart a container',
    description: 'Restart a running or stopped container',
  })
  @ApiBody({ type: DockerTagserverContainerControlDto })
  @ApiResponse({
    status: 200,
    description: 'Container restarted successfully',
  })
  async restart(@Body() dto: DockerTagserverContainerControlDto): Promise<CommandResponseDto> {
    return this.handler.handleRestart(dto);
  }

  @Post('delete')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Delete a container permanently',
    description: 'Delete a container and clean up its Nginx configuration',
  })
  @ApiBody({ type: DockerTagserverContainerControlDto })
  @ApiResponse({
    status: 200,
    description: 'Container deleted successfully',
  })
  async delete(@Body() dto: DockerTagserverContainerControlDto): Promise<CommandResponseDto> {
    return this.handler.handleDelete(dto);
  }

  @Post('logs')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get container logs',
    description: 'Get container logs (last 50 lines by default, or follow live)',
  })
  @ApiBody({ type: DockerTagserverLogsDto })
  @ApiResponse({
    status: 200,
    description: 'Container logs retrieved successfully',
  })
  async logs(@Body() dto: DockerTagserverLogsDto): Promise<CommandResponseDto> {
    return this.handler.handleLogs(dto);
  }

  @Post('add-custom-domain')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Add custom domains to a container',
    description: 'Add custom domains with automatic DNS verification',
  })
  @ApiBody({ type: DockerTagserverAddCustomDomainDto })
  @ApiResponse({
    status: 200,
    description: 'Custom domains added successfully',
  })
  async addCustomDomain(@Body() dto: DockerTagserverAddCustomDomainDto): Promise<CommandResponseDto> {
    return this.handler.handleAddCustomDomain(dto);
  }

  @Post('verify-dns-tasks')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Run DNS verification tasks',
    description: 'Run pending DNS verification tasks (typically used by cron)',
  })
  @ApiBody({ type: DockerTagserverVerifyDnsTasksDto })
  @ApiResponse({
    status: 200,
    description: 'DNS verification tasks completed',
  })
  async verifyDnsTasks(): Promise<CommandResponseDto> {
    return this.handler.handleVerifyDnsTasks();
  }

  @Post('count-usage')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Count log lines',
    description: 'Count total or pattern-matched log lines with optional date range filtering',
  })
  @ApiBody({ type: DockerTagserverCountLogsDto })
  @ApiResponse({
    status: 200,
    description: 'Log count retrieved successfully',
  })
  async countLogs(@Body() dto: DockerTagserverCountLogsDto): Promise<CommandResponseDto> {
    return this.handler.handleCountUsage(dto);
  }

  @Post('update-nginx')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Update Nginx configuration',
    description: 'Regenerate Nginx configuration for a container',
  })
  @ApiBody({ type: DockerTagserverUpdateNginxDto })
  @ApiResponse({
    status: 200,
    description: 'Nginx configuration updated successfully',
  })
  async updateNginx(@Body() dto: DockerTagserverUpdateNginxDto): Promise<CommandResponseDto> {
    return this.handler.handleUpdateNginx(dto);
  }
}
