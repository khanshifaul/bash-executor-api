import { Injectable, Logger } from '@nestjs/common';
import { spawn } from 'child_process';
import { CommandResponseDto } from '../../dto/command-response.dto';
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
  DockerTagserverRetrySslDto,
  DockerTagserverCronSetupDto,
} from './docker-tagserver.dto';

@Injectable()
export class DockerTagserverCommandHandler {
  private readonly logger = new Logger(DockerTagserverCommandHandler.name);

  /**
   * Create a new tag server container
   */
  async handleCreate(dto: DockerTagserverCreateDto): Promise<CommandResponseDto> {
    const cmd = [
      '/root/scripts/docker-tagserver.sh',
      'run',
      '-s',
      dto.domains,
      '-c',
      dto.config,
      '-n',
      dto.name,
      '-u',
      dto.user,
      '--json',
    ];
    return this.executeCommand(cmd);
  }

  /**
   * List containers for a user
   */
  async handleList(dto: DockerTagserverListDto): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'list', '--json'];
    if (dto.user) cmd.push('-u', dto.user);
    if (dto.all) cmd.push('-a');
    return this.executeCommand(cmd);
  }

  /**
   * Get details of a specific container
   */
  async handleGet(dto: DockerTagserverGetDto): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'get', '--json'];
    if (dto.containerId) cmd.push('-i', dto.containerId);
    if (dto.containerName) cmd.push('-n', dto.containerName);
    if (dto.user) cmd.push('-u', dto.user);
    return this.executeCommand(cmd);
  }

  /**
   * Stop a running container
   */
  async handleStop(dto: DockerTagserverContainerControlDto): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'stop', '--json'];
    if (dto.containerId) cmd.push('-i', dto.containerId);
    if (dto.containerName) cmd.push('-n', dto.containerName);
    if (dto.user) cmd.push('-u', dto.user);
    return this.executeCommand(cmd, true);
  }

  /**
   * Start a stopped container
   */
  async handleStart(dto: DockerTagserverContainerControlDto): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'start', '--json'];
    if (dto.containerId) cmd.push('-i', dto.containerId);
    if (dto.containerName) cmd.push('-n', dto.containerName);
    if (dto.user) cmd.push('-u', dto.user);
    return this.executeCommand(cmd, true);
  }

  /**
   * Restart a container
   */
  async handleRestart(dto: DockerTagserverContainerControlDto): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'restart', '--json'];
    if (dto.containerId) cmd.push('-i', dto.containerId);
    if (dto.containerName) cmd.push('-n', dto.containerName);
    if (dto.user) cmd.push('-u', dto.user);
    return this.executeCommand(cmd, true);
  }

  /**
   * Delete a container permanently
   */
  async handleDelete(dto: DockerTagserverContainerControlDto): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'delete', '--json'];
    if (dto.containerId) cmd.push('-i', dto.containerId);
    if (dto.containerName) cmd.push('-n', dto.containerName);
    if (dto.user) cmd.push('-u', dto.user);
    return this.executeCommand(cmd, true);
  }

  /**
   * Get container logs
   */
  async handleLogs(dto: DockerTagserverLogsDto): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'logs', '--json'];
    if (dto.containerId) cmd.push('-i', dto.containerId);
    if (dto.containerName) cmd.push('-n', dto.containerName);
    if (dto.user) cmd.push('-u', dto.user);

    return this.executeCommand(cmd);
  }

  /**
   * Add custom domains to a container
   */
  async handleAddCustomDomain(dto: DockerTagserverAddCustomDomainDto): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'add-custom-domain', '--json'];
    if (dto.containerId) cmd.push('-i', dto.containerId);
    if (dto.containerName) cmd.push('-n', dto.containerName);
    if (dto.user) cmd.push('-u', dto.user);
    cmd.push('-s', dto.domains.join(','));
    return this.executeCommand(cmd, true);
  }

  /**
   * Run DNS verification tasks
   */
  async handleVerifyDnsTasks(): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'verify-dns-tasks'];
    return this.executeCommand(cmd, true);
  }

  /**
   * Count usage
   */
  async handleCountUsage(dto: DockerTagserverCountLogsDto): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'count-usage', '--json'];
    if (dto.containerId) cmd.push('-i', dto.containerId);
    if (dto.containerName) cmd.push('-n', dto.containerName);
    if (dto.user) cmd.push('-u', dto.user);
    if (dto.all) cmd.push('-a');
    if (dto.pattern) cmd.push('-p', dto.pattern);
    if (dto.since) cmd.push('--since', dto.since);
    if (dto.until) cmd.push('--until', dto.until);
    return this.executeCommand(cmd);
  }

  /**
   * Update Nginx configuration
   */
  async handleUpdateNginx(dto: DockerTagserverUpdateNginxDto): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'update-nginx'];
    if (dto.containerId) cmd.push('-i', dto.containerId);
    if (dto.containerName) cmd.push('-n', dto.containerName);
    if (dto.user) cmd.push('-u', dto.user);
    return this.executeCommand(cmd, true);
  }

  /**
   * Retry SSL certificate generation for local fallbacks
   */
  async handleRetrySsl(dto: DockerTagserverRetrySslDto): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'retry-ssl'];
    if (dto.json !== false) cmd.push('--json');
    return this.executeCommand(cmd, true);
  }

  /**
   * Setup 3-hour cronjob for SSL retry
   */
  async handleCronSetup(): Promise<CommandResponseDto> {
    const cmd = ['/root/scripts/docker-tagserver.sh', 'cron-setup'];
    return this.executeCommand(cmd, true);
  }

  /**
   * Execute a command with spawn
   */
  private executeCommand(cmd: string[], requiresSudo: boolean = false): Promise<CommandResponseDto> {
    return new Promise<CommandResponseDto>((resolve) => {
      const startTime = Date.now();
      const fullCmd = requiresSudo ? ['sudo', ...cmd] : cmd;

      this.logger.debug(`Executing: ${fullCmd.join(' ')}`);

      const proc = spawn('bash', ['-c', fullCmd.join(' ')], {
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

      proc.on('close', (code: number | null) => {
        const exitCode = code ?? -1;
        resolve({
          stdout: this.tryParseJson(this.sanitizeOutput(stdout)),
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

      // 60 second timeout
      setTimeout(() => {
        proc.kill('SIGKILL');
      }, 60000);
    });
  }

  private sanitizeOutput(output: string): string {
    return output
      .replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '')
      .replace(/\x00/g, '')
      .replace(/\r/g, '\n')
      .substring(0, 10000);
  }

  private tryParseJson(str: string): any {
    const trimmed = str.trim();
    // 1. Try parsing the whole string first (fast path)
    try {
      if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        return JSON.parse(trimmed);
      }
    } catch (e) {
      // ignore
    }

    // 2. Try to find the last valid JSON object/array in the output
    // Split by newlines and check from the end, as valid JSON usually comes last in scripts
    try {
      const lines = trimmed.split('\n');
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i].trim();
        if ((line.startsWith('{') && line.endsWith('}')) || (line.startsWith('[') && line.endsWith(']'))) {
          try {
            return JSON.parse(line);
          } catch (e) {
            continue;
          }
        }
      }
    } catch (e) {
      // ignore
    }

    return str;
  }
}
