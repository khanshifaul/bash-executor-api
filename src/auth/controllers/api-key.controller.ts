import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  ParseUUIDPipe,
  HttpStatus,
  HttpCode,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { AccessTokenGuard } from '../../common/guards/access-token.guard';
import { User } from '../../common/decorators/user.decorator';
import { ApiKeyService } from '../services/api-key.service';
import { CreateApiKeyDto } from '../dto/create-api-key.dto';
import { UpdateApiKeyDto } from '../dto/update-api-key.dto';

@ApiTags('API Keys')
@ApiBearerAuth()
@Controller('auth/api-keys')
@UseGuards(AccessTokenGuard)
export class ApiKeyController {
  constructor(private readonly apiKeyService: ApiKeyService) {}

  @Post()
  @ApiOperation({ summary: 'Create a new API key' })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'API key created successfully',
  })
  @HttpCode(HttpStatus.CREATED)
  create(
    @User('id') userId: string,
    @Body() createApiKeyDto: CreateApiKeyDto,
  ) {
    return this.apiKeyService.create(userId, createApiKeyDto);
  }

  @Get()
  @ApiOperation({ summary: 'Get all active API keys for the user' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'List of API keys retrieved',
  })
  findAll(@User('id') userId: string) {
    return this.apiKeyService.findAll(userId);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a specific API key' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'API key retrieved',
  })
  findOne(@User('id') userId: string, @Param('id', ParseUUIDPipe) id: string) {
    return this.apiKeyService.findOne(userId, id);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update an API key' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'API key updated',
  })
  update(
    @User('id') userId: string,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updateApiKeyDto: UpdateApiKeyDto,
  ) {
    return this.apiKeyService.update(userId, id, updateApiKeyDto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete an API key' })
  @ApiResponse({
    status: HttpStatus.NO_CONTENT,
    description: 'API key deleted',
  })
  @HttpCode(HttpStatus.NO_CONTENT)
  remove(@User('id') userId: string, @Param('id', ParseUUIDPipe) id: string) {
    return this.apiKeyService.remove(userId, id);
  }
}