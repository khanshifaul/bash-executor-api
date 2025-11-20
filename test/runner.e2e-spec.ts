import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { DatabaseModule } from '../src/database/database.module';
import { RunnerModule } from '../src/runner/runner.module';

describe('Runner Module (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [RunnerModule, DatabaseModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('RunnerService', () => {
    it('should be defined', () => {
      const runnerService = app.get('RunnerService');
      expect(runnerService).toBeDefined();
    });

    it('should validate dangerous commands', async () => {
      const runnerService = app.get('RunnerService');
      const validation = await runnerService.validateCommand('rm -rf /');
      expect(validation.isValid).toBe(false);
      expect(validation.riskLevel).toBe('critical');
    });

    it('should allow safe commands', async () => {
      const runnerService = app.get('RunnerService');
      const validation = await runnerService.validateCommand('ls -la /tmp');
      expect(validation.isValid).toBe(true);
      expect(validation.riskLevel).toBe('low');
    });
  });

  describe('RunnerController', () => {
    it('should be defined', () => {
      const runnerController = app.get('RunnerController');
      expect(runnerController).toBeDefined();
    });
  });
});
