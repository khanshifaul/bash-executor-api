import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsNumber,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';

export class ExecuteScriptDto {
  @ApiProperty({
    description: 'The script content to execute',
    example: '#!/bin/bash\necho "Hello World"\nls -la',
  })
  @IsString()
  script: string;

  @ApiProperty({
    description: 'Script language (bash, sh, etc.)',
    example: 'bash',
    required: false,
    default: 'bash',
  })
  @IsOptional()
  @IsString()
  language?: string = 'bash';

  @ApiProperty({
    description: 'Script execution timeout in milliseconds',
    example: 60000,
    required: false,
    default: 60000,
  })
  @IsOptional()
  @IsNumber()
  @Min(1000)
  @Max(300000)
  timeout?: number = 60000;

  @ApiProperty({
    description: 'Working directory for script execution',
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
    example: 120,
    required: false,
    default: 120,
  })
  @IsOptional()
  @IsNumber()
  @Min(1)
  @Max(3600)
  maxExecutionTime?: number = 120;

  @ApiProperty({
    description: 'Save script to temporary file',
    example: true,
    required: false,
    default: true,
  })
  @IsOptional()
  @IsBoolean()
  saveToFile?: boolean = true;
}
