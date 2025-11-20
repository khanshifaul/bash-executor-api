import { Module, type DynamicModule, type Type } from '@nestjs/common';
import { DatabaseModule } from '../database/database.module';
import { RunnerController } from './runner.controller';
import { RunnerService } from './runner.service';
import { DockerTagserverModule } from './commands/docker-tagserver/docker-tagserver.module';

@Module({
  imports: [DatabaseModule, DockerTagserverModule],
  controllers: [RunnerController],
  providers: [RunnerService],
  exports: [RunnerService],
})
export class RunnerModule {}
