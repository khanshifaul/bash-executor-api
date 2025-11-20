import { CommandResponseDto } from 'src/runner/dto/command-response.dto';

export interface CommandHandler<T = unknown> {
  handle(command: T): Promise<CommandResponseDto>;
}
