import { Module } from '@nestjs/common';
import { DatabaseModule } from '../../../database/database.module';
import { DockerTagserverController } from './docker-tagserver.controller';
import { DockerTagserverCommandHandler } from './docker-tagserver.handler';

@Module({
  imports: [DatabaseModule],
  controllers: [DockerTagserverController],
  providers: [DockerTagserverCommandHandler],
  exports: [DockerTagserverCommandHandler],
})
export class DockerTagserverModule {}
