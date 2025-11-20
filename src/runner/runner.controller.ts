import {
  Body,
  Controller,
  DefaultValuePipe,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  NotFoundException,
  Param,
  ParseIntPipe,
  Post,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CommandResponseDto } from './dto/command-response.dto';
import { RunnerService } from './runner.service';

@ApiTags('Runner')
@ApiBearerAuth()
@UseGuards(AuthGuard('jwt'))
@Controller('runner')
export class RunnerController {
  constructor(private readonly runnerService: RunnerService) {}

  @Post('execute')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Execute a command or script',
    description:
      'Execute a single command string (`command`) or a script (`script`). Provide either `command` or `script` in the request body. Only bash scripts are supported via `script`.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        command: { type: 'string' },
        script: { type: 'string' },
        language: { type: 'string', example: 'bash' },
        timeout: { type: 'number' },
        workingDirectory: { type: 'string' },
      },
      additionalProperties: false,
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Execution result',
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
  @ApiResponse({ status: 400, description: 'Invalid request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async execute(
    @Body() body: any,
    @Request() req: any,
  ): Promise<CommandResponseDto> {
    const userId = req.user?.id;
    if (!userId) {
      throw new HttpException('Unauthorized', HttpStatus.UNAUTHORIZED);
    }

    const options = {
      cwd: body?.workingDirectory,
      timeout: body?.timeout,
    } as any;

    if (body?.command) {
      return this.runnerService.execute(body.command, options, userId);
    }

    if (body?.script) {
      if (body.language && body.language !== 'bash') {
        throw new HttpException('Only bash scripts are supported', HttpStatus.BAD_REQUEST);
      }
      // Execute script content directly via bash -c
      return this.runnerService.execute(body.script, options, userId);
    }

    throw new HttpException("Either 'command' or 'script' is required", HttpStatus.BAD_REQUEST);
  }

  @Get('history')
  @ApiOperation({
    summary: 'Get execution history for user',
    description:
      'Retrieve paginated execution history for the authenticated user',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Number of records to return (max 100)',
  })
  @ApiQuery({
    name: 'offset',
    required: false,
    type: Number,
    description: 'Number of records to skip',
  })
  @ApiResponse({
    status: 200,
    description: 'Execution history retrieved successfully',
    schema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          command: { type: 'string' },
          success: { type: 'boolean' },
          exitCode: { type: 'number' },
          executionTime: { type: 'number' },
          createdAt: { type: 'string', format: 'date-time' },
        },
      },
    },
  })
  async getExecutionHistory(
    @Request() req: any,
    @Query('limit', new DefaultValuePipe(50), ParseIntPipe) limit: number,
    @Query('offset', new DefaultValuePipe(0), ParseIntPipe) offset: number,
  ) {
    const userId = req.user.id;

    return this.runnerService.getExecutionHistory(userId, limit, offset);
  }

  @Get('history/:id')
  @ApiOperation({
    summary: 'Get specific execution details',
    description: 'Retrieve detailed information about a specific execution',
  })
  @ApiResponse({
    status: 200,
    description: 'Execution details retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        command: { type: 'string' },
        output: { type: 'string', nullable: true },
        success: { type: 'boolean' },
        exitCode: { type: 'number' },
        executionTime: { type: 'number' },
        userId: { type: 'string' },
        createdAt: { type: 'string', format: 'date-time' },
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: 'Execution log not found',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
        error: { type: 'string' },
        statusCode: { type: 'number' },
      },
    },
  })
  async getExecutionDetails(
    @Param('id') executionId: string,
    @Request() req: any,
  ) {
    const userId = req.user.id;

    return this.runnerService.getExecutionDetails(executionId, userId);
  }

  @Post('validate-command')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Validate command safety',
    description:
      'Check if a command passes security validation without executing it',
  })
  @ApiResponse({
    status: 200,
    description: 'Command validation completed',
    schema: {
      type: 'object',
      properties: {
        isValid: { type: 'boolean' },
        reasons: {
          type: 'array',
          items: { type: 'string' },
        },
        riskLevel: {
          type: 'string',
          enum: ['low', 'medium', 'high', 'critical'],
        },
      },
    },
  })
  async validateCommand() {
    throw new HttpException('Deprecated: use /runner/commands/<cmd>', HttpStatus.GONE);
  }

  // `POST /runner/cleanup-logs` endpoint removed.

  // Deprecated dynamic command execution endpoint removed.
}
