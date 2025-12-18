import {
  Injectable,
  Logger,
} from '@nestjs/common';
import { spawn } from 'child_process';
import { PrismaService } from '../database/prisma/prisma.service';
import { CommandResponseDto } from './dto/command-response.dto';
import { RunnerOptionsDto } from './dto/runner-options.dto';
import { CommandHandler } from './interfaces/command-handler.interface';

@Injectable()
export class RunnerService {
  private readonly logger = new Logger(RunnerService.name);
  private handlers = new Map<string, CommandHandler>();

  constructor(private prisma: PrismaService) {
    this.logger.log('RunnerService initialized');
  }

  getHandler(cmd: string): CommandHandler | undefined {
    const commandName = cmd.trim().split(/\s+/)[0].toLowerCase();
    return this.handlers.get(commandName);
  }

  async execRaw(command: string, options?: RunnerOptionsDto): Promise<CommandResponseDto> {
    return new Promise<CommandResponseDto>((resolve) => {
      const startTime = Date.now();
      const proc = spawn('bash', ['-c', command], {
        cwd: options?.cwd,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      proc.stderr?.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      proc.on('close', (code: number | null, signal: NodeJS.Signals | null) => {
        const exitCode = code ?? (signal === 'SIGKILL' ? 137 : -1);
        resolve({
          stdout: this.sanitizeOutput(stdout),
          stderr: this.sanitizeOutput(stderr),
          exitCode,
          duration: Date.now() - startTime,
        });
      });

      proc.on('error', (err: Error) => {
        resolve({
          stdout: this.sanitizeOutput(stdout),
          stderr: this.sanitizeOutput(err.message),
          exitCode: -1,
          duration: Date.now() - startTime,
        });
      });

      const timeoutMs = options?.timeout ?? 60000;
      setTimeout(() => {
        proc.kill('SIGKILL');
      }, timeoutMs);
    });
  }

  async execute(
    command: string,
    options: RunnerOptionsDto,
    userId: string,
  ): Promise<CommandResponseDto> {
    const handler = this.getHandler(command);
    let response: CommandResponseDto;
    if (handler) {
      response = await handler.handle({ command, options } as any);
    } else {
      response = await this.execRaw(command, options);
    }
    await this.logExecution(command, response, userId);
    return response;
  }

  private async logExecution(
    command: string,
    response: CommandResponseDto,
    userId: string,
  ) {
    try {
      const success = response.exitCode === 0;
      const stdoutStr =
        typeof response.stdout === 'string'
          ? response.stdout
          : JSON.stringify(response.stdout, null, 2);
      const output = `${stdoutStr}\n${response.stderr}`.trim();
      const sanitizedOutput = this.sanitizeOutput(output);
      await this.prisma.executionLog.create({
        data: {
          command,
          output: sanitizedOutput,
          success,
          exitCode: response.exitCode,
          executionTime: Math.floor(response.duration / 1000),
          userId,
        },
      });
    } catch (error) {
      this.logger.error('Failed to log execution', error as Error);
    }
  }

  private sanitizeOutput(output: string): string {
    return output
      .replace(/\x00/g, '')
      .replace(/\r/g, '\n')
      .substring(0, 10000);
  }

  async getExecutionHistory(
    userId: string,
    limit: number = 50,
    offset: number = 0,
  ) {
    try {
      const logs = await this.prisma.executionLog.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        skip: offset,
        take: Math.min(limit, 100),
        select: {
          id: true,
          command: true,
          success: true,
          exitCode: true,
          executionTime: true,
          createdAt: true,
        },
      });

      return logs;
    } catch (error) {
      this.logger.error('Failed to fetch execution history', error as Error);
      throw new Error('Failed to fetch execution history');
    }
  }

  async getExecutionDetails(executionId: string, userId: string) {
    try {
      const log = await this.prisma.executionLog.findFirst({
        where: {
          id: executionId,
          userId,
        },
        select: {
          id: true,
          command: true,
          output: true,
          success: true,
          exitCode: true,
          executionTime: true,
          userId: true,
          createdAt: true,
        },
      });

      if (!log) {
        throw new Error('Execution log not found');
      }

      return log;
    } catch (error) {
      this.logger.error('Failed to fetch execution details', error as Error);
      throw error instanceof Error && error.message === 'Execution log not found'
        ? error
        : new Error('Failed to fetch execution details');
    }
  }

  async cleanupOldLogs(daysToKeep: number = 30): Promise<number> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

      const result = await this.prisma.executionLog.deleteMany({
        where: {
          createdAt: {
            lt: cutoffDate,
          },
        },
      });

      const cleanedCount = result.count;
      this.logger.log(`Cleaned up ${cleanedCount} execution logs older than ${daysToKeep} days`);

      return cleanedCount;
    } catch (error) {
      this.logger.error('Failed to cleanup old logs', error as Error);
      throw new Error('Failed to cleanup old logs');
    }
  }
}
