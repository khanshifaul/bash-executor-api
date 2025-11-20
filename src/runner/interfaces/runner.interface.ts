export interface ExecutionResult {
  success: boolean;
  command: string;
  output?: string;
  error?: string;
  exitCode: number;
  executionTime: number;
  timestamp: Date;
}

export interface CommandValidationResult {
  isValid: boolean;
  reasons: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface SecurityConfig {
  maxCommandLength: number;
  maxExecutionTime: number;
  allowedCommands: string[];
  blockedCommands: string[];
  blockedPatterns: string[];
  allowedDirectories: string[];
}

export interface RunnerOptions {
  timeout: number;
  workingDirectory?: string;
  captureOutput: boolean;
  maxExecutionTime: number;
}
