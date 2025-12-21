import { Test, TestingModule } from '@nestjs/testing';
import { DockerTagserverCommandHandler } from './docker-tagserver.handler';
import * as child_process from 'child_process';
import { EventEmitter } from 'events';

describe('DockerTagserverCommandHandler', () => {
    let handler: DockerTagserverCommandHandler;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [DockerTagserverCommandHandler],
        }).compile();

        handler = module.get<DockerTagserverCommandHandler>(DockerTagserverCommandHandler);
    });

    it('should be defined', () => {
        expect(handler).toBeDefined();
    });

    describe('tryParseJson', () => {
        it('should parse valid JSON', () => {
            const json = '{"key": "value"}';
            expect(handler['tryParseJson'](json)).toEqual({ key: 'value' });
        });

        it('should parse JSON from mixed output (JSON at the end)', () => {
            const mixed = 'Some logs here\nMore logs\n{"key": "value"}';
            expect(handler['tryParseJson'](mixed)).toEqual({ key: 'value' });
        });

        it('should return original string if no valid JSON is found', () => {
            const plain = 'Just some logs';
            expect(handler['tryParseJson'](plain)).toBe(plain);
        });

        it('should find the last valid JSON in mixed output', () => {
            const mixed = '{"first": 1}\nSome logs\n{"second": 2}\nExtra text';
            expect(handler['tryParseJson'](mixed)).toEqual({ second: 2 });
        });

        it('should parse JSON arrays', () => {
            const array = '[{"id": 1}, {"id": 2}]';
            expect(handler['tryParseJson'](array)).toEqual([{ id: 1 }, { id: 2 }]);
        });
    });

    describe('executeCommand', () => {
        let spawnSpy: jest.SpyInstance;

        beforeEach(() => {
            spawnSpy = jest.spyOn(child_process, 'spawn');
        });

        afterEach(() => {
            spawnSpy.mockRestore();
        });

        it('should execute command and return results', async () => {
            const mockStdout = new EventEmitter();
            const mockStderr = new EventEmitter();
            const mockProc = new EventEmitter() as any;
            mockProc.stdout = mockStdout;
            mockProc.stderr = mockStderr;
            mockProc.kill = jest.fn();

            spawnSpy.mockReturnValue(mockProc);

            const promise = handler.handleList({ user: 'user123' });

            process.nextTick(() => {
                mockStdout.emit('data', Buffer.from('[{"id": "c1"}]'));
                mockProc.emit('close', 0);
            });

            const result = await promise;
            expect(result.exitCode).toBe(0);
            expect(result.stdout).toEqual([{ id: 'c1' }]);
            expect(spawnSpy).toHaveBeenCalledWith(
                'bash',
                ['-c', expect.stringContaining('list --json -u user123')],
                expect.anything(),
            );
        });

        it('should handle command errors', async () => {
            const mockStdout = new EventEmitter();
            const mockStderr = new EventEmitter();
            const mockProc = new EventEmitter() as any;
            mockProc.stdout = mockStdout;
            mockProc.stderr = mockStderr;
            mockProc.kill = jest.fn();

            spawnSpy.mockReturnValue(mockProc);

            const promise = handler.handleDelete({ containerId: 'c1' });

            process.nextTick(() => {
                mockStderr.emit('data', Buffer.from('Error deleting'));
                mockProc.emit('close', 1);
            });

            const result = await promise;
            expect(result.exitCode).toBe(1);
            expect(result.stderr).toContain('Error deleting');
        });
    });
});
