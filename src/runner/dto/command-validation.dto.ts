import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsOptional, IsString } from 'class-validator';

export class CommandValidationDto {
  @ApiProperty({
    description: 'The command to validate',
    example: 'ls -la /tmp',
  })
  @IsString()
  command: string;

  @ApiProperty({
    description: 'Check against whitelist instead of blacklist',
    example: false,
    required: false,
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  useWhitelist?: boolean = false;

  @ApiProperty({
    description: 'Enable strict validation mode',
    example: false,
    required: false,
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  strict?: boolean = false;
}
