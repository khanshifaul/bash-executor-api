import { Test, TestingModule } from '@nestjs/testing';
import { DockerTagserverController } from './docker-tagserver.controller';
import { DockerTagserverCommandHandler } from './docker-tagserver.handler';
import { DockerTagserverCreateDto, DockerTagserverListDto } from './docker-tagserver.dto';

describe('DockerTagserverController', () => {
    let controller: DockerTagserverController;
    let handler: DockerTagserverCommandHandler;

    const mockHandler = {
        handleCreate: jest.fn(),
        handleList: jest.fn(),
        handleGet: jest.fn(),
        handleStop: jest.fn(),
        handleStart: jest.fn(),
        handleRestart: jest.fn(),
        handleDelete: jest.fn(),
        handleLogs: jest.fn(),
        handleAddCustomDomain: jest.fn(),
        handleVerifyDnsTasks: jest.fn(),
        handleCountLogs: jest.fn(),
        handleUpdateNginx: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [DockerTagserverController],
            providers: [
                {
                    provide: DockerTagserverCommandHandler,
                    useValue: mockHandler,
                },
            ],
        }).compile();

        controller = module.get<DockerTagserverController>(DockerTagserverController);
        handler = module.get<DockerTagserverCommandHandler>(DockerTagserverCommandHandler);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });

    it('should call handleCreate with correct dto', async () => {
        const dto: DockerTagserverCreateDto = { domains: 'test.com', config: 'cfg', name: 'n1', user: 'u1' };
        await controller.create(dto);
        expect(handler.handleCreate).toHaveBeenCalledWith(dto);
    });

    it('should call handleList with correct dto', async () => {
        const dto: DockerTagserverListDto = { user: 'user123' };
        await controller.list(dto);
        expect(handler.handleList).toHaveBeenCalledWith(dto);
    });
});
