import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsNumber,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';

export class ExecuteCommandDto {
  @ApiProperty({
    description: 'The bash command to execute',
    example: 'ls -la /tmp',
  })
  @IsString()
  command: string;

  @ApiProperty({
    description: 'Command execution timeout in milliseconds',
    example: 30000,
    required: false,
    default: 30000,
  })
  @IsOptional()
  @IsNumber()
  @Min(1000)
  @Max(300000)
  timeout?: number = 30000;

  @ApiProperty({
    description: 'Working directory for command execution',
    example: '/tmp',
    required: false,
  })
  @IsOptional()
  @IsString()
  workingDirectory?: string;

  @ApiProperty({
    description: 'Capture stdout and stderr',
    example: true,
    required: false,
    default: true,
  })
  @IsOptional()
  @IsBoolean()
  captureOutput?: boolean = true;

  @ApiProperty({
    description: 'Maximum allowed execution time in seconds',
    example: 60,
    required: false,
    default: 60,
  })
  @IsOptional()
  @IsNumber()
  @Min(1)
  @Max(3600)
  maxExecutionTime?: number = 60;
}
