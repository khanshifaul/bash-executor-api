# Docker Tagserver Commands Module

## Architecture Overview

The docker-tagserver commands module is a modular, extensible command execution system built on NestJS. It provides a structured approach to defining, validating, and executing docker-tagserver CLI commands through REST API endpoints.

## Key Features

- **Modular Command Structure**: Each command is independently defined and can be extended
- **Type-Safe DTOs**: All commands have validated input/output types using class-validator
- **Swagger Documentation**: All endpoints are automatically documented with OpenAPI/Swagger
- **Security Guards**: Built-in command-level access control
- **Automatic Discovery**: New command modules are automatically discovered and registered
- **Standardized Responses**: All commands return consistent response formats

## Directory Structure

```
src/runner/
├── commands/
│   ├── base/
│   │   ├── command-base.guard.ts
│   │   ├── command-base.module.ts
│   │   └── ...
│   ├── ls/
│   │   ├── ls.controller.ts
│   │   ├── ls.handler.ts
│   │   ├── ls.dto.ts
│   │   └── ls.module.ts
│   ├── cat/
│   │   ├── cat.controller.ts
│   │   ├── cat.handler.ts
│   │   ├── cat.dto.ts
│   │   └── cat.module.ts
│   └── docker-tagserver/
│       ├── docker-tagserver.controller.ts
│       ├── docker-tagserver.handler.ts
│       ├── docker-tagserver.dto.ts
│       ├── docker-tagserver.module.ts
│       └── base/
│           ├── docker-tagserver-base.interface.ts
│           ├── validators.ts
│           └── docker-tagserver-base.module.ts
├── runner.controller.ts
├── runner.service.ts
├── runner.module.ts
└── ...
```

## Docker Tagserver Commands

### Available Endpoints

All endpoints are prefixed with `/commands/docker-tagserver/` and require Bearer token authentication.

#### 1. Create Container
- **Endpoint**: `POST /commands/docker-tagserver/create`
- **Description**: Start a new tag server container with domain routing and SSL
- **Request Body**:
  ```json
  {
    "domains": "example.com sub.example.com",
    "config": "config-name",
    "name": "container-name",
    "user": "username"
  }
  ```

#### 2. List Containers
- **Endpoint**: `POST /commands/docker-tagserver/list`
- **Description**: List all containers for a user
- **Request Body**:
  ```json
  {
    "user": "username",
    "all": false
  }
  ```

#### 3. Get Container Details
- **Endpoint**: `POST /commands/docker-tagserver/get`
- **Description**: Get detailed information about a specific container
- **Request Body**:
  ```json
  {
    "containerId": "container-id"
  }
  ```
  OR
  ```json
  {
    "containerName": "container-name"
  }
  ```

#### 4. Stop Container
- **Endpoint**: `POST /commands/docker-tagserver/stop`
- **Description**: Stop a running container
- **Request Body**: Same as Get Container Details

#### 5. Start Container
- **Endpoint**: `POST /commands/docker-tagserver/start`
- **Description**: Start a stopped container
- **Request Body**: Same as Get Container Details

#### 6. Restart Container
- **Endpoint**: `POST /commands/docker-tagserver/restart`
- **Description**: Restart a container
- **Request Body**: Same as Get Container Details

#### 7. Delete Container
- **Endpoint**: `POST /commands/docker-tagserver/delete`
- **Description**: Delete a container permanently and clean up Nginx config
- **Request Body**: Same as Get Container Details

#### 8. Get Container Logs
- **Endpoint**: `POST /commands/docker-tagserver/logs`
- **Description**: Get container logs
- **Request Body**:
  ```json
  {
    "containerId": "container-id",
    "follow": false
  }
  ```

#### 9. Add Custom Domains
- **Endpoint**: `POST /commands/docker-tagserver/add-custom-domain`
- **Description**: Add custom domains with DNS verification
- **Request Body**:
  ```json
  {
    "containerId": "container-id",
    "domains": ["domain1.com", "domain2.com"]
  }
  ```

#### 10. Verify DNS Tasks
- **Endpoint**: `POST /commands/docker-tagserver/verify-dns-tasks`
- **Description**: Run pending DNS verification tasks
- **Request Body**: `{}`

#### 11. Count Logs
- **Endpoint**: `POST /commands/docker-tagserver/count-logs`
- **Description**: Count total or pattern-matched log lines
- **Request Body**:
  ```json
  {
    "containerId": "container-id",
    "pattern": "ERROR",
    "since": "2025-01-01",
    "until": "2025-01-31"
  }
  ```

#### 12. Update Nginx
- **Endpoint**: `POST /commands/docker-tagserver/update-nginx`
- **Description**: Regenerate Nginx configuration
- **Request Body**:
  ```json
  {
    "containerId": "container-id"
  }
  ```

## Response Format

All commands return a standardized response:

```json
{
  "stdout": "command output",
  "stderr": "error output if any",
  "exitCode": 0,
  "duration": 1234
}
```

## Creating a New Command Module

To add a new command module, follow this pattern:

### 1. Create DTOs
```
src/runner/
├── commands/
│   ├── base/
│   │   ├── command-base.guard.ts
│   │   ├── command-base.module.ts
│   │   └── ...
│   └── docker-tagserver/
│       ├── docker-tagserver.controller.ts
│       ├── docker-tagserver.handler.ts
│       ├── docker-tagserver.dto.ts
│       ├── docker-tagserver.module.ts
│       └── base/
│           ├── docker-tagserver-base.interface.ts
│           ├── validators.ts
│           └── docker-tagserver-base.module.ts
src/runner.controller.ts
src/runner.service.ts
src/runner.module.ts
└── ...
```
@Controller('commands/my-command')
export class MyCommandController {
  constructor(private readonly handler: MyCommandHandler) {}

  @Post()
  @ApiOperation({ summary: 'Execute my command' })
  @ApiBody({ type: MyCommandDto })
  async execute(@Body() dto: MyCommandDto): Promise<CommandResponseDto> {
    return this.handler.handle(dto);
  }
}
```

### 4. Create Module
```typescript
// my-command.module.ts
@Module({
  imports: [DatabaseModule],
  controllers: [MyCommandController],
  providers: [MyCommandHandler],
  exports: [MyCommandHandler],
})
export class MyCommandModule {}
```

### 5. Update RunnerModule
The RunnerModule uses auto-discovery, so simply adding your module to the commands directory will register it automatically through the scan function.

## Swagger Documentation

All commands are automatically documented in Swagger UI. Access it at:
```
GET /api/docs
```

Each endpoint includes:
- Operation summary and description
- Request/response schemas
- Error responses
- Authentication requirements

## Security

- All endpoints require JWT Bearer token authentication
- Commands are validated through CommandBaseGuard
- Container identifiers prevent access to unauthorized containers
- User validation prevents running commands as 'root'
- Reserved container names are blocked

## Testing

Run the test suite:
```bash
npm run test
```

E2E tests:
```bash
npm run test:e2e
```

## Migration from Old Architecture

### Old Way (Deprecated)
```
POST /runner/commands/ls
POST /runner/commands/cat
```

### New Way
```
POST /commands/ls
POST /commands/cat
POST /commands/docker-tagserver/create
POST /commands/docker-tagserver/list
```

The old generic endpoint `/runner/commands/:cmd` is now deprecated and returns a 410 Gone status with instructions to use the new specific command endpoints.
