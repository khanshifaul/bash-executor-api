import { IsOptional, IsString, IsInt, Min } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class RunnerOptionsDto {
  @ApiPropertyOptional({ description: 'Working directory' })
  @IsOptional()
  @IsString()
  cwd?: string;

  @ApiPropertyOptional({ description: 'Timeout in ms' })
  @IsOptional()
  @IsInt()
  @Min(1000)
  timeout?: number;
}