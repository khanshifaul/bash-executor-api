# Runner Module

The Runner Module provides secure bash command execution capabilities for the Bash Runner API. It includes comprehensive security features, command validation, and execution logging.

## Features

### 🔒 Security Features

- **Dangerous Command Detection**: Blocks potentially harmful commands (rm -rf, mkfs, etc.)
- **Command Injection Prevention**: Validates against shell metacharacters and injection patterns
- **Whitelist/Blacklist System**: Supports both allowlist and blocklist validation
- **Output Sanitization**: Cleans command output to prevent security risks
- **User Isolation**: Each user only sees their own execution history

### ⚡ Command Execution

- **Async Execution**: Non-blocking command execution with proper timeouts
- **Output Capture**: Captures stdout and stderr with configurable options
- **Execution Tracking**: Monitors execution time and exit codes
- **Resource Limits**: Configurable timeouts and buffer limits

### 📊 Logging & History

- **Execution Logging**: All commands are logged to database with metadata
- **History Retrieval**: Paginated access to execution history
- **Detailed Views**: Access to specific execution details including output
- **Log Cleanup**: Automated cleanup of old execution logs

## API Endpoints

### POST /runner/execute

Execute a single bash command with security validation.

**Request Body:**

```json
{
  "command": "ls -la /tmp",
  "timeout": 30000,
  "workingDirectory": "/tmp",
  "captureOutput": true,
  "maxExecutionTime": 60
}
```

**Response:**

```json
{
  "success": true,
  "command": "ls -la /tmp",
  "output": "total 8\ndrwxrwxrwt 2 root root 4096 Nov 18 10:50 .\ndrwxr-xr-x 1 root root 4096 Nov 18 08:32 ..",
  "exitCode": 0,
  "executionTime": 150,
  "timestamp": "2025-11-18T10:50:34.497Z"
}
```

### POST /runner/execute-script

Execute a script from content (bash or python).

**Request Body:**

```json
{
  "script": "#!/bin/bash\necho 'Hello World'\nls -la",
  "language": "bash",
  "timeout": 60000,
  "saveToFile": true
}
```

### GET /runner/history

Get execution history for the authenticated user.

**Query Parameters:**

- `limit` (optional): Number of records to return (max 100, default 50)
- `offset` (optional): Number of records to skip (default 0)

### GET /runner/history/:id

Get specific execution details including full output.

### POST /runner/validate-command

Validate a command without executing it.

**Request Body:**

```json
{
  "command": "rm -rf /tmp",
  "useWhitelist": false,
  "strict": false
}
```

**Response:**

```json
{
  "isValid": false,
  "reasons": ["Dangerous command detected: rm -rf"],
  "riskLevel": "critical"
}
```

## Security Configuration

### Dangerous Commands Blocked

The following commands are automatically blocked:

- File system operations: `rm -rf`, `mkfs`, `dd`, `shred`
- System operations: `sudo`, `su`, `reboot`, `shutdown`
- Network operations: `ssh`, `scp`, `curl -X POST`
- Docker/Kubernetes: `docker run`, `kubectl`
- Cloud services: `aws s3`, `gcloud`, `az`

### Blocked Patterns

- Shell metacharacters: `;`, `&`, `|`, `` ` ``, `$`, `(`, `)`
- Variable substitution: `${...}`
- Command substitution: `` `...` ``
- Directory traversal: `../`
- Command chaining: `&&`, `||`

### Allowed Commands

Safe commands that are typically allowed:

- System info: `ls`, `pwd`, `whoami`, `id`, `uname`
- File viewing: `cat`, `head`, `tail`, `wc`
- Text processing: `grep`, `find`, `sort`, `uniq`
- System monitoring: `df`, `du`, `free`, `uptime`

## Configuration

### Environment Variables

- `RUNNER_MAX_COMMAND_LENGTH`: Maximum command length (default: 1000)
- `RUNNER_MAX_EXECUTION_TIME`: Maximum execution timeout (default: 60000ms)

### Working Directories

Commands can only execute in these directories:

- `/tmp`
- `/var/tmp`
- Current working directory
- User's home directory

## Usage Example

```typescript
import { RunnerService } from './runner/runner.service';

// Execute a safe command
const result = await runnerService.executeCommand(
  'ls -la /tmp',
  { timeout: 30000, captureOutput: true },
  'user-id',
);

if (result.success) {
  console.log('Output:', result.output);
} else {
  console.error('Error:', result.error);
}

// Validate a command before execution
const validation = await runnerService.validateCommand('echo "Hello World"');
if (validation.isValid) {
  // Safe to execute
}
```

## Error Handling

The module provides comprehensive error handling:

- **BadRequestException**: Invalid input or validation failure
- **ForbiddenException**: Command rejected by security validation
- **Timeout handling**: Commands exceeding timeout limits

## Database Schema

Execution logs are stored in the `execution_logs` table:

- `id`: Unique execution ID
- `command`: The executed command
- `output`: Captured output (sanitized)
- `success`: Whether execution was successful
- `exitCode`: Command exit code
- `executionTime`: Execution time in seconds
- `userId`: User who executed the command
- `createdAt`: Execution timestamp

## Testing

Unit tests and e2e tests are available:

- `test/runner.e2e-spec.ts`: End-to-end testing
- Security validation tests
- Command execution tests
- Integration tests with database

Run tests:

```bash
npm run test src/runner
npm run test:e2e test/runner.e2e-spec.ts
```

## Integration

The module integrates with:

- **Database Module**: For logging execution history
- **Auth Module**: JWT authentication for user isolation
- **Config Module**: Environment configuration
- **Prisma**: Database operations for execution logs
